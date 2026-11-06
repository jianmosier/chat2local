use crate::{Context, Result, Stop, V, fail};
pub fn active_session(cx: &mut Context<'_>, actor: &V) -> Result<()> {
    cx.exact(actor, &["identityKey", "sessionBinding"])?;
    let identity = p(cx, actor, "identityKey")?;
    let binding = p(cx, actor, "sessionBinding")?;
    if !identity.hex(64) || !binding.hex(64) {
        return fail("Verified account required.", 401);
    }
    let bound = cx.read(format!("onboarding:v1:session-binding:{}", binding.text()))?;
    if !bound.truthy()
        || p(cx, &bound, "identityKey")? != identity
        || numeric(&p(cx, &bound, "until")?)? <= cx.now()?
    {
        return fail(
            "Account sign-in expired or was signed out. No pending share was activated.",
            401,
        );
    }
    Ok(())
}
pub fn p(cx: &Context<'_>, v: &V, k: &str) -> Result<V> {
    cx.property(v, k)
}
pub fn numeric(v: &V) -> Result<f64> {
    if !matches!(v, V::Number(_)) || !v.number().is_finite() {
        Err(Stop::Invalid)
    } else {
        Ok(v.number())
    }
}
pub fn array_or_empty(cx: &Context<'_>, v: &V) -> Result<Vec<V>> {
    if v.truthy() { cx.array(v) } else { Ok(vec![]) }
}
pub fn sort(cx: &mut Context<'_>, values: Vec<V>, keys: Vec<V>, locale: bool) -> Result<Vec<V>> {
    let input = cx.list(keys);
    let result = cx.compute(if locale { "localeSort" } else { "sort" }, input)?;
    let order = cx.array(&result)?;
    if order.len() != values.len() {
        return Err(Stop::Invalid);
    }
    let mut seen = vec![];
    let mut out = vec![];
    for index in order {
        let n = numeric(&index)?;
        if n.fract() != 0.0 || n < 0.0 || n >= values.len() as f64 || seen.contains(&(n as usize)) {
            return Err(Stop::Invalid);
        }
        seen.push(n as usize);
        out.push(values[n as usize].clone());
    }
    Ok(out)
}
pub fn scopes(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let values = cx.array(input)?;
    let mut seen = vec![];
    if values.len() > 4 || !values.iter().any(|s| s.is("files:read")) {
        return fail("Invalid connection scopes.", 400);
    }
    for v in &values {
        if ![
            "files:read",
            "files:write",
            "files:propose",
            "terminal:execute",
        ]
        .iter()
        .any(|s| v.is(s))
            || seen.contains(v)
        {
            return fail("Invalid connection scopes.", 400);
        }
        seen.push(v.clone());
    }
    let sorted = sort(cx, values.clone(), values, false)?;
    Ok(cx.list(sorted))
}
pub fn client(input: &V) -> Result<V> {
    if let V::String(s) = input
        && !s.is_empty()
        && s.len() <= 512
        && !s.iter().any(|n| *n <= 32 || *n == 127)
    {
        return Ok(input.clone());
    }
    fail("Invalid client identity.", 400)
}
pub fn resource(cx: &mut Context<'_>, input: &V) -> Result<V> {
    if input.length().is_none_or(|n| n > 2048) {
        return fail("Invalid connection resource.", 400);
    }
    let url = cx.compute("parseUrl", input.clone())?;
    let protocol = p(cx, &url, "protocol")?;
    let host = p(cx, &url, "hostname")?;
    let loopback = protocol.is("http:")
        && ["127.0.0.1", "localhost", "[::1]"]
            .iter()
            .any(|s| host.is(s));
    if (!protocol.is("https:") && !loopback)
        || p(cx, &url, "username")?.truthy()
        || p(cx, &url, "password")?.truthy()
        || p(cx, &url, "search")?.truthy()
        || p(cx, &url, "hash")?.truthy()
        || !p(cx, &url, "pathname")?.is("/mcp")
        || p(cx, &url, "href")? != *input
    {
        return fail(
            "Connection resource must be a canonical HTTPS MCP endpoint (or isolated loopback).",
            400,
        );
    }
    Ok(input.clone())
}
pub fn shares(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let values = cx.array(input)?;
    if values.is_empty() || values.len() > 50 {
        return fail("Select specific shared folders.", 400);
    }
    let mut seen = vec![];
    let mut out = vec![];
    let mut keys = vec![];
    for root in values {
        cx.exact(&root, &["rootId", "mode"])?;
        let id = p(cx, &root, "rootId")?;
        let mode = p(cx, &root, "mode")?;
        let valid = matches!(&id,V::String(s)if !s.is_empty()&&s.len()<=80&&s.iter().all(|u|matches!(*u,48..=57|65..=90|97..=122|45|95)));
        if !valid
            || seen.contains(&id)
            || !["read-only", "review", "direct"].iter().any(|s| mode.is(s))
        {
            return fail("Invalid or duplicate shared folder.", 400);
        }
        seen.push(id.clone());
        keys.push(id);
        out.push(cx.spread(&root, vec![])?);
    }
    let sorted = sort(cx, out, keys, true)?;
    Ok(cx.list(sorted))
}
pub fn grant(cx: &mut Context<'_>, connection: &V, requested: V) -> Result<V> {
    let account = p(cx, connection, "accountId")?;
    let id = p(cx, connection, "id")?;
    let epoch = p(cx, connection, "epoch")?;
    if !account.hex(32) || !id.hex(32) || !epoch.hex(64) {
        return fail("Invalid account connection grant.", 400);
    }
    let c = client(&p(cx, connection, "clientId")?)?;
    let r = resource(cx, &p(cx, connection, "resource")?)?;
    let s = scopes(cx, &requested)?;
    Ok(cx.object(vec![
        ("grantVersion", V::num(3.0)),
        ("accountId", account),
        ("connectionId", id),
        ("connectionEpoch", epoch),
        ("clientId", c),
        ("resource", r),
        ("scopes", s),
    ]))
}
