use crate::common::{numeric, p};
use crate::{Context, Result, Stop, V, fail};
fn key(kind: &str, id: &V) -> String {
    format!(
        "install:v1:{kind}{}{}",
        if id == &V::Undefined { "" } else { ":" },
        if id == &V::Undefined {
            String::new()
        } else {
            id.text()
        }
    )
}
fn equal(a: &V, b: &V) -> bool {
    if !a.hex(64) || !b.hex(64) {
        return false;
    }
    let (V::String(a), V::String(b)) = (a, b) else {
        return false;
    };
    let mut diff = 0u16;
    for (a, b) in a.iter().zip(b) {
        diff |= a ^ b
    }
    diff == 0
}
fn session(cx: &mut Context<'_>, secret: &V) -> Result<V> {
    if !secret.hex(64) {
        return fail("请输入你自己的实例安装密码。", 401);
    }
    let hash = cx.compute("sha256", secret.clone())?;
    let session = cx.read(key("session", &hash))?;
    let config = cx.read(key("password", &V::Undefined))?;
    if !session.truthy()
        || numeric(&p(cx, &session, "until")?)? <= cx.now()?
        || p(cx, &session, "epoch")? != cx.get(&config, "epoch")
    {
        return fail("安装登录已过期，请重新登录。", 401);
    }
    Ok(session)
}
fn ticket(cx: &mut Context<'_>, id: &V, secret: &V, kind: &str) -> Result<V> {
    if !id.hex(32) || !secret.hex(64) {
        return fail("Invalid installer proof.", 401);
    }
    let value = cx.read(key("ticket", id))?;
    if !value.truthy() || numeric(&p(cx, &value, "until")?)? <= cx.now()? {
        return fail(
            "Installer request expired or belongs to another computer.",
            401,
        );
    }
    let digest = cx.compute("sha256", secret.clone())?;
    if !equal(&p(cx, &value, kind)?, &digest) {
        return fail(
            "Installer request expired or belongs to another computer.",
            401,
        );
    }
    Ok(value)
}
fn cleanup(
    cx: &mut Context<'_>,
    kind: &str,
    limit: usize,
    capacity: usize,
    message: &str,
) -> Result<()> {
    let rows = cx.rows(&key(kind, &V::str("")), limit)?;
    for row in &rows {
        if numeric(&p(cx, &p(cx, row, "value")?, "until")?)? <= cx.now()? {
            cx.delete(p(cx, row, "key")?.text())?
        }
    }
    let mut active = 0;
    for row in &rows {
        if numeric(&p(cx, &p(cx, row, "value")?, "until")?)? > cx.now()? {
            active += 1
        }
    }
    if active >= capacity {
        return fail(message, 429);
    }
    Ok(())
}
pub fn execute(cx: &mut Context<'_>, op: &str, input: &V) -> Result<V> {
    cx.branch = op.trim_start_matches("install.").into();
    match op {
        "install.password.configure" => {
            if cx.read(key("password", &V::Undefined))?.truthy() {
                return fail("安装密码已经设置；没有覆盖。", 409);
            }
            let epoch = cx.random("secret")?;
            let record = cx.object(vec![
                ("salt", p(cx, input, "salt")?),
                ("digest", p(cx, input, "digest")?),
                ("epoch", epoch),
            ]);
            cx.put(key("password", &V::Undefined), record)?;
            Ok(cx.object(vec![
                ("configured", V::Bool(true)),
                ("fileAccessGranted", V::Bool(false)),
            ]))
        }
        "install.rate.consume" => rate(cx, input),
        "install.session.create" => {
            let current = cx.read(key("password", &V::Undefined))?;
            let config = p(cx, input, "config")?;
            if cx.get(&current, "epoch") != p(cx, &config, "epoch")? {
                return fail("Installer login changed.", 401);
            }
            cleanup(cx, "session", 65, 64, "Too many installer sessions.")?;
            let until = cx.now()? + 1800000.0;
            let record = cx.object(vec![
                ("epoch", p(cx, &config, "epoch")?),
                ("until", V::num(until)),
            ]);
            cx.put(key("session", &p(cx, input, "sessionHash")?), record)?;
            Ok(V::Undefined)
        }
        "install.ticket.create" => create_ticket(cx, &p(cx, input, "input")?),
        "install.context.ticket" => ticket(
            cx,
            &p(cx, input, "id")?,
            &p(cx, input, "browser")?,
            "browserHash",
        ),
        "install.context.session" => session(cx, &p(cx, input, "session")?),
        "install.authorize.check" => {
            session(cx, &p(cx, input, "session")?)?;
            ticket(
                cx,
                &p(cx, input, "id")?,
                &p(cx, input, "browser")?,
                "browserHash",
            )
        }
        "install.authorize.pin" | "install.authorize.advance" => {
            session(cx, &p(cx, input, "session")?)?;
            let id = p(cx, input, "id")?;
            let current = ticket(cx, &id, &p(cx, input, "browser")?, "browserHash")?;
            let selected = p(cx, input, "selectedConnectionId")?;
            let previous = p(cx, &current, "connectionId")?;
            if op == "install.authorize.pin" {
                if previous.truthy() && previous != selected {
                    return fail("Installer target is already pinned.", 409);
                }
                cx.set(&current, "connectionId", selected)?;
            } else {
                if previous != selected {
                    return fail("Installer connection changed.", 409);
                }
                if p(cx, &current, "phase")?.is("pending") {
                    cx.set(&current, "phase", V::str("authorized"))?
                }
            }
            cx.put(key("ticket", &id), current)?;
            Ok(V::Undefined)
        }
        "install.claim.ticket" => ticket(
            cx,
            &p(cx, input, "id")?,
            &p(cx, input, "secret")?,
            "claimHash",
        ),
        "install.ticket.ready" => {
            let id = p(cx, input, "id")?;
            let item = ticket(cx, &id, &p(cx, input, "secret")?, "claimHash")?;
            let phase = p(cx, &item, "phase")?;
            if !phase.is("authorized") && !phase.is("ready") {
                return fail("Installer has no approved connection.", 403);
            }
            cx.set(&item, "phase", V::str("ready"))?;
            cx.put(key("ticket", &id), item)?;
            Ok(cx.object(vec![
                ("ready", V::Bool(true)),
                ("foldersGranted", V::Bool(false)),
            ]))
        }
        _ => Err(Stop::Invalid),
    }
}
fn rate(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let storage_key = key("rate", &p(cx, input, "bucket")?);
    let mut rate = cx.read(storage_key.clone())?;
    let rows = cx.rows("install:v1:rate:", 129)?;
    for row in &rows {
        if numeric(&p(cx, &p(cx, row, "value")?, "until")?)? <= cx.now()? {
            cx.delete(p(cx, row, "key")?.text())?
        }
    }
    if !rate.truthy() {
        let mut alive = 0;
        for row in &rows {
            if numeric(&p(cx, &p(cx, row, "value")?, "until")?)? > cx.now()? {
                alive += 1
            }
        }
        if alive >= 128 {
            return fail("Installer login is busy.", 429);
        }
    }
    if !rate.truthy() || numeric(&p(cx, &rate, "until")?)? <= cx.now()? {
        let until = cx.now()? + numeric(&p(cx, input, "windowMs")?)?;
        rate = cx.object(vec![("count", V::num(0.0)), ("until", V::num(until))]);
    }
    let count = numeric(&p(cx, &rate, "count")?)?;
    if count >= numeric(&p(cx, input, "limit")?)? {
        return fail("尝试过多，请稍后再试；没有更改现有连接。", 429);
    }
    cx.set(&rate, "count", V::num(count + 1.0))?;
    cx.put(storage_key, rate)?;
    Ok(V::Undefined)
}
fn create_ticket(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let id = p(cx, input, "id")?;
    let storage_key = key("ticket", &id);
    let previous = cx.read(storage_key.clone())?;
    if previous.truthy() {
        if ["claimHash", "browserHash", "name"]
            .iter()
            .any(|k| cx.get(&previous, k) != cx.get(input, k))
            || numeric(&p(cx, &previous, "until")?)? <= cx.now()?
        {
            return fail("Installer request changed or expired.", 409);
        }
        cx.branch = "ticket-idempotent".into();
        return Ok(cx.object(vec![
            ("id", p(cx, &previous, "id")?),
            ("until", p(cx, &previous, "until")?),
        ]));
    }
    cleanup(cx, "ticket", 65, 64, "Too many pending installers.")?;
    let until = cx.now()? + 600000.0;
    let value = cx.spread(
        input,
        vec![
            ("until", V::num(until)),
            ("phase", V::str("pending")),
            ("connectionId", V::Null),
        ],
    )?;
    cx.put(storage_key, value.clone())?;
    Ok(cx.object(vec![
        ("id", p(cx, &value, "id")?),
        ("until", p(cx, &value, "until")?),
    ]))
}
