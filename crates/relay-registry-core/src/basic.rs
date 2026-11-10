use crate::{Context, Result, Stop, V, fail};
fn number(value: &V) -> Result<f64> {
    match value {
        V::Number(_) | V::Null | V::Bool(_) => {
            let n = value.number();
            if n.is_finite() {
                Ok(n)
            } else {
                Err(Stop::Invalid)
            }
        }
        _ => Err(Stop::Invalid),
    }
}
fn optional_number(value: &V) -> Result<f64> {
    if matches!(value, V::Undefined) {
        Ok(f64::NAN)
    } else {
        number(value)
    }
}
fn reserve(cx: &mut Context<'_>, prefix: &str) -> Result<()> {
    let rows = cx.rows(prefix, 257)?;
    let mut expired = vec![];
    for row in &rows {
        let item = cx.get(row, "value");
        if optional_number(&cx.property(&item, "expiresAt")?)? <= cx.now()? {
            expired.push(cx.get(row, "key").text());
        }
    }
    let count = expired.len();
    cx.delete_many(expired)?;
    if rows.len() - count >= 200 {
        cx.branch = "capacity".into();
        return fail("Too many pending browser connections.", 429);
    }
    Ok(())
}
fn devices(cx: &mut Context<'_>, value: &V) -> Result<Vec<V>> {
    let items = cx.array(value)?;
    if items.is_empty() || items.len() > 20 {
        cx.branch = "invalid".into();
        return fail("Invalid authorized device set.", 400);
    }
    let mut seen = vec![];
    let mut out = vec![];
    for item in items {
        let id = cx.get(&item, "deviceId");
        let epoch = cx.get(&item, "epoch");
        if !id.hex(32) || !epoch.hex(64) || seen.contains(&id) {
            cx.branch = "invalid".into();
            return fail("Invalid or duplicate authorized device.", 400);
        }
        seen.push(id.clone());
        let original = cx.get(&item, "description");
        let mut props = vec![];
        for field in ["name", "platform", "arch", "system"] {
            let v = cx.get(&original, field);
            if let V::String(units) = &v
                && !units.is_empty()
                && units.len() <= 128
                && !units.iter().any(|u| *u < 32 || *u == 127)
            {
                props.push((field, v));
            }
        }
        let description = cx.object(props);
        out.push(cx.object(vec![
            ("deviceId", id),
            ("epoch", epoch),
            ("description", description),
        ]));
    }
    Ok(out)
}
pub fn execute(cx: &mut Context<'_>, op: &str, a: &V) -> Result<V> {
    match op {
        "registry.selfEnroll" => {
            let value = cx.get(a, "value");
            let id = cx.get(&value, "deviceId");
            let key_hash = cx.get(&value, "keyHash");
            let ip_hash = cx.get(&value, "ipHash");
            let previous = cx.read(format!("device:{}", id.text()))?;
            if previous.truthy() {
                cx.branch = "existing".into();
                return Ok(
                    if cx.get(&previous, "kind").is("self")
                        && cx.get(&previous, "keyHash") == key_hash
                    {
                        cx.ok()
                    } else {
                        cx.reject(409, "Identity already exists.")
                    },
                );
            }
            let c = cx.read("deviceCount".into())?;
            let count = if c.nullish() { V::num(0.0) } else { c };
            let s = cx.read("selfDeviceCount".into())?;
            let self_count = if s.nullish() { V::num(0.0) } else { s };
            if number(&count)? >= 100.0 || number(&self_count)? >= cx.get(a, "limit").number() {
                cx.branch = "quota".into();
                return Ok(cx.reject(429, "New device registration is full."));
            }
            let now = cx.now()?;
            let observed = cx.read("selfRates".into())?;
            let original = if observed.nullish() {
                vec![]
            } else {
                cx.array(&observed)?
            };
            let mut rates = vec![];
            for r in original {
                if r == V::Hole {
                    continue;
                }
                if optional_number(&cx.property(&r, "until")?)? > now {
                    rates.push(r);
                }
            }
            let rate = if let Some(r) = rates.iter().find(|r| cx.get(r, "ipHash") == ip_hash) {
                r.clone()
            } else {
                if rates.len() >= 100 {
                    cx.branch = "rate-capacity".into();
                    return Ok(cx.reject(429, "Registration is busy."));
                }
                let r = cx.object(vec![
                    ("ipHash", ip_hash),
                    ("count", V::num(0.0)),
                    ("until", V::num(now + 3_600_000.0)),
                ]);
                rates.push(r.clone());
                r
            };
            if number(&cx.property(&rate, "count")?)? >= 3.0 {
                cx.branch = "rate-denied".into();
                return Ok(cx.reject(429, "Registration limit reached for this network."));
            }
            cx.set(
                &rate,
                "count",
                V::num(number(&cx.property(&rate, "count")?)? + 1.0),
            )?;
            let rates = cx.list(rates);
            cx.put("selfRates".into(), rates)?;
            cx.put("deviceCount".into(), count.plus_one())?;
            cx.put("selfDeviceCount".into(), self_count.plus_one())?;
            let device = cx.object(vec![("kind", V::str("self")), ("keyHash", key_hash)]);
            cx.put(format!("device:{}", id.text()), device)?;
            cx.branch = "created".into();
            Ok(cx.ok())
        }
        "registry.enroll" => {
            let value = cx.get(a, "value");
            let c = cx.read("deviceCount".into())?;
            let count = if c.nullish() { V::num(0.0) } else { c };
            let key = format!("device:{}", cx.get(&value, "deviceId").text());
            if number(&count)? >= 100.0 || cx.read(key.clone())?.truthy() {
                cx.branch = "denied".into();
                return Ok(cx.reject(409, "Device quota exceeded or identity already enrolled."));
            }
            cx.put("deviceCount".into(), count.plus_one())?;
            cx.put(key, V::Bool(true))?;
            cx.branch = "created".into();
            Ok(cx.ok())
        }
        "registry.ticket.inspect" => {
            let key = cx.get(a, "key").text();
            let ticket = cx.read(key.clone())?;
            if !ticket.truthy() || number(&cx.property(&ticket, "expiresAt")?)? <= cx.now()? {
                cx.branch = "invalid".into();
                return Ok(cx.reject(403, "Consent expired or invalid."));
            }
            let csrf = cx.get(a, "csrf");
            let digest = cx.compute("sha256", csrf)?;
            if digest != cx.get(&ticket, "csrfHash") {
                cx.branch = "invalid".into();
                return Ok(cx.reject(403, "Consent expired or invalid."));
            }
            if cx.get(a, "consume") == V::Bool(true) {
                cx.delete(key)?;
                cx.branch = "consumed".into()
            } else {
                cx.branch = "peek".into()
            };
            Ok(cx.http(200, ticket, V::Null))
        }
        "budget.consume" => {
            let key = cx.get(a, "key").text();
            let now = cx.get(a, "now").number();
            let old = cx.read(key.clone())?;
            let record = if !old.truthy() || number(&cx.property(&old, "until")?)? <= now {
                cx.object(vec![
                    ("count", V::num(0.0)),
                    ("until", V::num(now + 3_600_000.0)),
                ])
            } else {
                old
            };
            if number(&cx.property(&record, "count")?)? >= cx.get(a, "limit").number() {
                cx.branch = "denied".into();
                let retry = ((cx.get(&record, "until").number() - now) / 1000.0)
                    .ceil()
                    .max(1.0);
                let body = cx.object(vec![
                    (
                        "error",
                        V::str("Relay request budget exceeded; retry later."),
                    ),
                    ("retryAfterSeconds", V::num(retry)),
                ]);
                let headers = cx.object(vec![("Retry-After", V::str(&retry.to_string()))]);
                return Ok(cx.http(429, body, headers));
            }
            cx.set(
                &record,
                "count",
                V::num(number(&cx.property(&record, "count")?)? + 1.0),
            )?;
            cx.put(key, record)?;
            cx.branch = "allowed".into();
            Ok(cx.ok())
        }
        "roster.linkTicket.create" => {
            let value = cx.get(a, "value");
            reserve(cx, "link-ticket:")?;
            let expiry = cx.now()? + 300000.0;
            let ticket = cx.object(vec![
                ("proofHash", cx.get(&value, "proofHash")),
                ("previousHash", cx.get(&value, "previousHash")),
                ("expiresAt", V::num(expiry)),
            ]);
            cx.put(
                format!("link-ticket:{}", cx.get(&value, "csrfHash").text()),
                ticket,
            )?;
            cx.branch = "created".into();
            Ok(cx.ok())
        }
        "roster.linkTicket.consume" => {
            let value = cx.get(a, "value");
            let key = format!("link-ticket:{}", cx.get(&value, "csrfHash").text());
            let ticket = cx.read(key.clone())?;
            if !ticket.truthy()
                || number(&cx.property(&ticket, "expiresAt")?)? <= cx.now()?
                || cx.get(&ticket, "proofHash") != cx.get(&value, "proofHash")
                || cx.get(&ticket, "previousHash") != cx.get(&value, "previousHash")
            {
                cx.branch = "invalid".into();
                return Ok(cx.reject(403, "Browser or target changed. Restart the connection."));
            }
            cx.delete(key)?;
            cx.branch = "consumed".into();
            Ok(cx.ok())
        }
        "roster.append" => {
            let value = cx.get(a, "value");
            let target = cx.get(a, "target");
            let previous_hash = cx.get(&value, "previousHash");
            let previous = if previous_hash.truthy() {
                cx.read(format!("browser-roster:{}", previous_hash.text()))?
            } else {
                V::Null
            };
            let mut all = if optional_number(&cx.get(&previous, "expiresAt"))? > cx.now()? {
                devices(cx, &cx.get(&previous, "devices"))?
            } else {
                vec![]
            };
            all.retain(|d| cx.get(d, "deviceId") != cx.get(&target, "deviceId"));
            if all.len() >= 20 {
                cx.branch = "device-limit".into();
                return Ok(cx.reject(409, "Too many computers in this browser session."));
            }
            reserve(cx, "browser-roster:")?;
            all.push(target);
            let count = all.len();
            let devices = cx.list(all);
            let expiry = cx.now()? + 900000.0;
            let record = cx.object(vec![("devices", devices), ("expiresAt", V::num(expiry))]);
            let session = cx.get(&value, "sessionHash");
            cx.put(format!("browser-roster:{}", session.text()), record)?;
            if previous_hash.truthy() && previous_hash != session {
                cx.delete(format!("browser-roster:{}", previous_hash.text()))?
            }
            cx.branch = "appended".into();
            let body = cx.object(vec![
                ("ok", V::Bool(true)),
                ("deviceCount", V::num(count as f64)),
            ]);
            Ok(cx.http(200, body, V::Null))
        }
        _ => Err(Stop::Invalid),
    }
}
