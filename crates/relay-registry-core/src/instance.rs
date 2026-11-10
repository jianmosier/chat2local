use crate::common::{array_or_empty, numeric, p};
use crate::{Context, Result, Stop, V, fail};
pub fn key(kind: &str, id: &V) -> String {
    format!("instance:v1:{kind}:{}", id.text())
}
fn account(kind: &str, id: &V) -> String {
    format!("accounts:v3:{kind}:{}", id.text())
}
fn yes(cx: &mut Context<'_>, name: &str) -> V {
    cx.object(vec![(name, V::Bool(true))])
}
fn registered(cx: &Context<'_>, registration: &V, device: &V) -> Result<bool> {
    Ok(*registration == V::Bool(true)
        || (cx.get(registration, "kind").is("private-instance")
            && p(cx, registration, "keyHash")? == p(cx, device, "keyHash")?))
}
fn contains(cx: &Context<'_>, list: &V, value: &V) -> Result<bool> {
    Ok(cx.array(list)?.contains(value))
}
pub fn check_invite(cx: &mut Context<'_>, resource: &V, id: &V, secret: &V, flow: &V) -> Result<V> {
    let item = cx.read(key("invite", id))?;
    if !item.truthy()
        || p(cx, &item, "resource")? != *resource
        || p(cx, &item, "secretHash")? != *secret
        || p(cx, &item, "revoked")?.truthy()
    {
        return fail("Invitation invalid or revoked.", 403);
    }
    let claim = p(cx, &item, "claim")?;
    if claim.truthy() {
        if p(cx, &claim, "flowId")? != *flow
            || numeric(&p(cx, &item, "resumeUntil")?)? <= cx.now()?
        {
            return fail("Invitation already used by another setup or expired.", 403);
        }
    } else if numeric(&p(cx, &item, "expiresAt")?)? <= cx.now()? {
        return fail("Invitation expired.", 403);
    }
    let connection_id = p(cx, &item, "connectionId")?;
    if connection_id.truthy() {
        let connection = cx.read(account("connection", &connection_id))?;
        if !connection.truthy()
            || p(cx, &connection, "revoked")?.truthy()
            || p(cx, &connection, "epoch")? != p(cx, &item, "connectionEpoch")?
            || p(cx, &connection, "accountId")? != p(cx, &item, "accountId")?
            || p(cx, &connection, "resource")? != *resource
            || p(cx, &connection, "clientId")? != p(cx, &item, "clientId")?
        {
            return fail("Invited connection was revoked or changed.", 403);
        }
        for scope in cx.array(&p(cx, &item, "scopes")?)? {
            if !contains(cx, &p(cx, &connection, "scopes")?, &scope)? {
                return fail("Invited connection was revoked or changed.", 403);
            }
        }
    }
    Ok(item)
}
pub fn assert_flow(cx: &mut Context<'_>, resource: &V, flow: &V) -> Result<()> {
    let current = cx.read(key("flow", &p(cx, flow, "id")?))?;
    let device = cx.get(&current, "device");
    let expected = cx.get(flow, "device");
    if !current.truthy()
        || numeric(&p(cx, &current, "until")?)? <= cx.now()?
        || p(cx, &current, "cancelled")?.truthy()
        || ["deviceId", "sessionHash", "epoch"]
            .iter()
            .any(|k| cx.get(&device, k) != cx.get(&expected, k))
    {
        return fail(
            "Native pairing has expired, changed or been cancelled.",
            403,
        );
    }
    if p(cx, &current, "reuseExisting")?.truthy() || p(cx, &current, "manageExisting")?.truthy() {
        let registration = cx.read(format!("device:{}", p(cx, &device, "deviceId")?.text()))?;
        if !registered(cx, &registration, &device)? {
            return fail("The previously enrolled device is unavailable.", 403);
        }
        let id = p(cx, &current, "connectionId")?;
        if id.truthy() {
            let connection = cx.read(account("connection", &id))?;
            if !connection.truthy()
                || p(cx, &connection, "revoked")?.truthy()
                || p(cx, &connection, "epoch")? != p(cx, &current, "recoveryEpoch")?
                || p(cx, &connection, "accountId")? != p(cx, &current, "accountId")?
                || p(cx, &connection, "resource")? != *resource
                || p(cx, &connection, "clientId")?
                    != p(cx, &p(cx, &current, "authRequest")?, "clientId")?
            {
                return fail(
                    "The original private connection changed or was revoked.",
                    403,
                );
            }
            for scope in cx.array(&p(cx, &current, "scopes")?)? {
                if !contains(cx, &p(cx, &connection, "scopes")?, &scope)?
                    && !(p(cx, &current, "mode")?.is("oauth")
                        && p(cx, &current, "allowScopeUpgrade")? == V::Bool(true)
                        && scope.is("terminal:execute"))
                {
                    return fail(
                        "The original private connection changed or was revoked.",
                        403,
                    );
                }
            }
            if p(cx, &connection, "revision")? != p(cx, &current, "recoveryRevision")?
                && !cx
                    .array(&p(cx, &connection, "shares")?)?
                    .iter()
                    .any(|s| cx.get(s, "intentId") == cx.get(&current, "id"))
            {
                return fail(
                    "Shared folders changed after recovery started; stale authorization was not restored.",
                    403,
                );
            }
        }
    } else {
        check_invite(
            cx,
            resource,
            &p(cx, &current, "invitationId")?,
            &p(cx, &current, "invitationHash")?,
            &p(cx, &current, "id")?,
        )?;
    }
    if p(cx, &current, "mode")?.is("oauth") && !p(cx, &current, "connectionId")?.truthy() {
        let ids = cx.read(account("connection-index", &p(cx, &current, "accountId")?))?;
        for id in array_or_empty(cx, &ids)? {
            let existing = cx.read(account("connection", &id))?;
            if existing.truthy()
                && !p(cx, &existing, "revoked")?.truthy()
                && p(cx, &existing, "clientId")?
                    == p(cx, &p(cx, &current, "authRequest")?, "clientId")?
                && p(cx, &existing, "resource")? == *resource
            {
                let mut found = false;
                for share in cx.array(&p(cx, &existing, "shares")?)? {
                    if p(cx, &share, "intentId")? == p(cx, &current, "id")? {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return fail(
                        "This client already has a private connection. Use its join invitation; no second connection was created.",
                        409,
                    );
                }
            }
        }
    }
    Ok(())
}
fn cleanup(
    cx: &mut Context<'_>,
    kind: &str,
    limit: usize,
    capacity: usize,
    mode: &str,
    message: &str,
) -> Result<bool> {
    let rows = cx.rows(&key(kind, &V::str("")), limit)?;
    for row in &rows {
        let item = p(cx, row, "value")?;
        let expiry = expiry(cx, &item, mode)?;
        if expiry <= cx.now()? {
            cx.delete(p(cx, row, "key")?.text())?
        }
    }
    let mut count = 0;
    for row in &rows {
        if expiry(cx, &p(cx, row, "value")?, mode)? > cx.now()? {
            count += 1
        }
    }
    if count >= capacity {
        if kind == "remember" {
            return Ok(false);
        }
        return fail(message, 429);
    }
    Ok(true)
}
fn expiry(cx: &Context<'_>, item: &V, mode: &str) -> Result<f64> {
    match mode {
        "invite" => numeric(&p(
            cx,
            item,
            if p(cx, item, "claim")?.truthy() {
                "resumeUntil"
            } else {
                "expiresAt"
            },
        )?),
        "flow" => {
            if p(cx, item, "device")?.truthy() {
                numeric(&p(cx, item, "until")?)
            } else {
                Ok(numeric(&p(cx, item, "createdAt")?)? + 300000.0)
            }
        }
        _ => numeric(&p(cx, item, "until")?),
    }
}
pub fn execute(cx: &mut Context<'_>, op: &str, input: &V) -> Result<V> {
    cx.branch = op.trim_start_matches("instance.").into();
    let resource = p(cx, input, "resource")?;
    match op {
        "instance.owner.ensure" => {
            let mut value = cx.read(key("owner", &V::str("")))?;
            if value.truthy() && p(cx, &value, "resource")? != resource {
                return fail(
                    "Private instance origin changed; explicit migration required.",
                    403,
                );
            }
            if !value.truthy() {
                let identity = cx.random("secret")?;
                let binding = cx.random("secret")?;
                value = cx.object(vec![
                    ("resource", resource),
                    ("identityKey", identity),
                    ("sessionBinding", binding),
                ]);
                cx.put(key("owner", &V::str("")), value.clone())?;
            }
            Ok(value)
        }
        "instance.invitation.create" => invitation_create(cx, input),
        "instance.invitation.revoke" => {
            let id = p(cx, input, "invitationId")?;
            let item = cx.read(key("invite", &id))?;
            if !item.truthy() {
                return fail("Invitation not found.", 404);
            }
            cx.set(&item, "revoked", V::Bool(true))?;
            cx.put(key("invite", &id), item)?;
            Ok(cx.object(vec![
                ("revoked", V::Bool(true)),
                ("activeSharesChanged", V::Bool(false)),
            ]))
        }
        "instance.invitation.pin" => check_invite(
            cx,
            &resource,
            &p(cx, input, "invitationId")?,
            &p(cx, input, "digest")?,
            &V::Null,
        ),
        "instance.flow.create" => {
            cleanup(
                cx,
                "flow",
                201,
                200,
                "flow",
                "Too many pending connection requests.",
            )?;
            cx.put(key("flow", &p(cx, input, "flowId")?), p(cx, input, "flow")?)?;
            Ok(V::Undefined)
        }
        "instance.invitation.claim" => claim(cx, input),
        "instance.recovery.claim" => recovery(cx, input),
        "instance.native.bindEpoch" => {
            let id = p(cx, input, "flowId")?;
            let flow = cx.read(key("flow", &id))?;
            let bound = p(cx, &flow, "device")?;
            let device = p(cx, input, "device")?;
            let epoch = p(cx, &bound, "epoch")?;
            if epoch.truthy() && epoch != p(cx, &device, "epoch")? {
                return fail("Device epoch changed.", 403);
            }
            cx.set(&bound, "epoch", p(cx, &device, "epoch")?)?;
            cx.put(key("flow", &id), flow.clone())?;
            native_view(cx, &resource, &flow, &device, None)
        }
        "instance.finish.take" => {
            let flow = p(cx, input, "flow")?;
            assert_flow(cx, &resource, &flow)?;
            let id = p(cx, input, "flowId")?;
            let current = cx.read(key("flow", &id))?;
            if p(cx, &current, "finishTaken")?.truthy() {
                return fail("OAuth continuation already consumed.", 409);
            }
            cx.set(&current, "finishTaken", V::Bool(true))?;
            cx.put(key("flow", &id), current)?;
            Ok(V::Undefined)
        }
        "instance.remember.store" => {
            if !cleanup(cx, "remember", 65, 64, "until", "")? {
                cx.branch = "remember-full".into();
                return Ok(V::Undefined);
            }
            let hash = cx.compute("sha256", p(cx, input, "remember")?)?;
            let until = cx.now()? + 30.0 * 86400000.0;
            let record = cx.object(vec![
                ("grant", p(cx, input, "grant")?),
                ("redirectUri", p(cx, input, "redirectUri")?),
                ("until", V::num(until)),
            ]);
            cx.put(key("remember", &hash), record)?;
            Ok(V::Undefined)
        }
        "instance.shares.remove" => remove(cx, input),
        "instance.manage" => manage(cx, input),
        _ => Err(Stop::Invalid),
    }
}
fn invitation_create(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let id = p(cx, input, "invitationId")?;
    let value = p(cx, input, "value")?;
    let previous = cx.read(key("invite", &id))?;
    if previous.truthy() {
        let mut same = p(cx, input, "stable")?.truthy()
            && !p(cx, &previous, "revoked")?.truthy()
            && numeric(&p(cx, &previous, "expiresAt")?)? > cx.now()?;
        for k in [
            "secretHash",
            "resource",
            "purpose",
            "connectionId",
            "connectionEpoch",
            "clientId",
        ] {
            if same && p(cx, &previous, k)? != p(cx, &value, k)? {
                same = false
            }
        }
        if same {
            let a = cx.compute("jsonText", p(cx, &previous, "scopes")?)?;
            let b = cx.compute("jsonText", p(cx, &value, "scopes")?)?;
            same = a == b
        }
        if !same {
            return fail("Installer invitation changed, expired or revoked.", 409);
        }
        cx.branch = "invitation-idempotent".into();
        return Ok(previous);
    }
    cleanup(
        cx,
        "invite",
        65,
        64,
        "invite",
        "Too many current invitations.",
    )?;
    cx.put(key("invite", &id), value.clone())?;
    Ok(value)
}
fn claim(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let id = p(cx, input, "flowId")?;
    let resource = p(cx, input, "resource")?;
    let flow = cx.read(key("flow", &id))?;
    if !flow.truthy()
        || p(cx, &flow, "bootstrapHash")? != p(cx, input, "bootstrapHash")?
        || numeric(&p(cx, &flow, "until")?)? <= cx.now()?
        || (!p(cx, &flow, "device")?.truthy()
            && cx.now()? - numeric(&p(cx, &flow, "createdAt")?)? > 300000.0)
    {
        return fail("This native connection request expired.", 401);
    }
    let supplied = p(cx, input, "supplied")?;
    let previous = p(cx, &flow, "invitationId")?;
    let invitation = if previous.truthy() {
        previous
    } else {
        cx.get(&supplied, "id")
    };
    let previous = p(cx, &flow, "invitationHash")?;
    let hash = if previous.truthy() {
        previous
    } else {
        cx.get(&supplied, "hash")
    };
    if !invitation.truthy()
        || (p(cx, &flow, "mode")?.is("oauth")
            && supplied.truthy()
            && (p(cx, &supplied, "id")? != invitation || p(cx, &supplied, "hash")? != hash))
    {
        return fail("Use this private instance’s installation invitation.", 403);
    }
    let invite = check_invite(cx, &resource, &invitation, &hash, &id)?;
    if p(cx, &invite, "accountId")? != p(cx, &flow, "accountId")?
        || p(cx, &flow, "mode")?.is("join") != p(cx, &invite, "purpose")?.is("join")
        || (p(cx, &invite, "clientId")?.truthy()
            && p(cx, &invite, "clientId")? != p(cx, &p(cx, &flow, "authRequest")?, "clientId")?)
    {
        return fail(
            "Invitation client or permissions do not match this request.",
            403,
        );
    }
    for scope in cx.array(&p(cx, &flow, "scopes")?)? {
        if !contains(cx, &p(cx, &invite, "scopes")?, &scope)? {
            return fail(
                "Invitation client or permissions do not match this request.",
                403,
            );
        }
    }
    let device = p(cx, input, "deviceId")?;
    let key_hash = p(cx, input, "keyHash")?;
    let session = p(cx, input, "sessionHash")?;
    let claim = cx.object(vec![
        ("flowId", id.clone()),
        ("deviceId", device.clone()),
        ("keyHash", key_hash.clone()),
        ("sessionHash", session.clone()),
    ]);
    let old = p(cx, &invite, "claim")?;
    if old.truthy() {
        let a = cx.compute("jsonText", old)?;
        let b = cx.compute("jsonText", claim.clone())?;
        if a != b {
            return fail(
                "Invitation is already bound to a different device or native session.",
                403,
            );
        }
    }
    if p(cx, input, "registering")?.truthy() {
        let registration = cx.read(format!("device:{}", device.text()))?;
        if registration.truthy() {
            if !p(cx, &registration, "kind")?.is("private-instance")
                || p(cx, &registration, "invitationId")? != p(cx, &invite, "id")?
                || p(cx, &registration, "keyHash")? != key_hash
            {
                return fail("Existing device identity cannot be replaced.", 409);
            }
        } else {
            let raw = cx.read("deviceCount".into())?;
            let count = if raw.truthy() { numeric(&raw)? } else { 0.0 };
            if count >= 100.0 {
                return fail("Private device limit reached.", 429);
            }
            let record = cx.object(vec![
                ("kind", V::str("private-instance")),
                ("invitationId", p(cx, &invite, "id")?),
                ("keyHash", key_hash.clone()),
            ]);
            cx.put(format!("device:{}", device.text()), record)?;
            cx.put("deviceCount".into(), V::num(count + 1.0))?;
        }
    }
    cx.set(&invite, "claim", claim)?;
    if !p(cx, &invite, "resumeUntil")?.truthy() {
        let until = cx.now()? + 86400000.0;
        cx.set(&invite, "resumeUntil", V::num(until))?
    }
    for (field, from) in [
        ("invitationId", "id"),
        ("invitationHash", "secretHash"),
        ("connectionId", "connectionId"),
    ] {
        cx.set(&flow, field, p(cx, &invite, from)?)?
    }
    if !p(cx, &flow, "device")?.truthy() {
        let record = cx.object(vec![
            ("deviceId", device.clone()),
            ("keyHash", key_hash.clone()),
            ("sessionHash", session.clone()),
        ]);
        cx.set(&flow, "device", record)?
    }
    let bound = p(cx, &flow, "device")?;
    if p(cx, &bound, "deviceId")? != device
        || p(cx, &bound, "keyHash")? != key_hash
        || p(cx, &bound, "sessionHash")? != session
    {
        return fail("Native device changed during setup.", 403);
    }
    cx.put(key("invite", &p(cx, &invite, "id")?), invite)?;
    cx.put(key("flow", &p(cx, &flow, "id")?), flow)?;
    Ok(yes(cx, "reserved"))
}
fn recovery(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let id = p(cx, input, "flowId")?;
    let resource = p(cx, input, "resource")?;
    let flow = cx.read(key("flow", &id))?;
    if !flow.truthy()
        || p(cx, &flow, "bootstrapHash")? != p(cx, input, "bootstrapHash")?
        || numeric(&p(cx, &flow, "until")?)? <= cx.now()?
        || (!p(cx, &flow, "device")?.truthy()
            && cx.now()? - numeric(&p(cx, &flow, "createdAt")?)? > 300000.0)
    {
        return fail("This native connection request expired.", 401);
    }
    if !p(cx, &flow, "mode")?.is("oauth")
        || (p(cx, &flow, "device")?.truthy() && !p(cx, &flow, "reuseExisting")?.truthy())
    {
        return Ok(V::Bool(false));
    }
    let device = p(cx, input, "device")?;
    let session = p(cx, input, "sessionHash")?;
    let registration = cx.read(format!("device:{}", p(cx, &device, "deviceId")?.text()))?;
    let legacy = registration == V::Bool(true);
    if !registered(cx, &registration, &device)? {
        return Ok(V::Bool(false));
    }
    if p(cx, &flow, "reuseExisting")?.truthy() {
        let saved = p(cx, &flow, "device")?;
        if ["deviceId", "keyHash", "epoch"]
            .iter()
            .any(|k| cx.get(&saved, k) != cx.get(&device, k))
            || p(cx, &saved, "sessionHash")? != session
        {
            return fail("Recovery belongs to another native device or session.", 403);
        }
        assert_flow(cx, &resource, &flow)?;
        return Ok(V::Bool(true));
    }
    let ids = cx.read(account("connection-index", &p(cx, &flow, "accountId")?))?;
    let mut matching = vec![];
    for id in array_or_empty(cx, &ids)? {
        let connection = cx.read(account("connection", &id))?;
        if connection.truthy()
            && p(cx, &connection, "clientId")? == p(cx, &p(cx, &flow, "authRequest")?, "clientId")?
            && p(cx, &connection, "resource")? == resource
        {
            matching.push(connection)
        }
    }
    if matching.len() > 1 || matching.iter().any(|c| cx.get(c, "revoked").truthy()) {
        return fail(
            "The previous connection was revoked or is ambiguous; explicit management is required.",
            403,
        );
    }
    let connection = matching.first().cloned().unwrap_or(V::Undefined);
    let mut shares = vec![];
    let mut added = vec![];
    if connection.truthy() {
        for share in cx.array(&p(cx, &connection, "shares")?)? {
            if p(cx, &share, "deviceId")? == p(cx, &device, "deviceId")?
                && p(cx, &share, "deviceEpoch")? == p(cx, &device, "epoch")?
            {
                shares.push(share)
            }
        }
        for scope in cx.array(&p(cx, &flow, "scopes")?)? {
            if !contains(cx, &p(cx, &connection, "scopes")?, &scope)? {
                added.push(scope)
            }
        }
    }
    let upgrade = added.len() == 1 && added[0].is("terminal:execute");
    if connection.truthy() && (shares.is_empty() || (!added.is_empty() && !upgrade)) {
        return fail(
            "This device or requested scope is not in the existing connection; access was not expanded.",
            403,
        );
    }
    if upgrade {
        cx.set(&flow, "allowScopeUpgrade", V::Bool(true))?
    }
    if !connection.truthy() && !legacy {
        return Ok(V::Bool(false));
    }
    cx.set(&flow, "reuseExisting", V::Bool(true))?;
    for (field, from) in [("connectionId", "id"), ("recoveryEpoch", "epoch")] {
        let value = cx.get(&connection, from);
        cx.set(&flow, field, if value.truthy() { value } else { V::Null })?
    }
    let revision = cx.get(&connection, "revision");
    cx.set(
        &flow,
        "recoveryRevision",
        if matches!(revision, V::Null | V::Undefined) {
            V::Null
        } else {
            revision
        },
    )?;
    let roots = if connection.truthy() {
        let mut roots = vec![];
        for share in shares {
            roots.push(cx.object(vec![
                ("rootId", p(cx, &share, "rootId")?),
                ("mode", p(cx, &share, "mode")?),
            ]))
        }
        cx.list(roots)
    } else {
        V::Null
    };
    cx.set(&flow, "recoveryRoots", roots)?;
    let bound = cx.object(vec![
        ("deviceId", p(cx, &device, "deviceId")?),
        ("keyHash", p(cx, &device, "keyHash")?),
        ("epoch", p(cx, &device, "epoch")?),
        ("sessionHash", session),
    ]);
    cx.set(&flow, "device", bound)?;
    cx.put(key("flow", &id), flow)?;
    Ok(V::Bool(true))
}
fn native_view(
    cx: &mut Context<'_>,
    resource: &V,
    flow: &V,
    device: &V,
    management: Option<(&V, &V)>,
) -> Result<V> {
    let url = cx.compute("parseUrl", resource.clone())?;
    let auth = p(cx, flow, "authRequest")?;
    let hash = cx.compute("jsonSha256", auth.clone())?;
    let callback = cx.compute(
        "parseUrl",
        p(
            cx,
            management.map_or(&auth, |(_, descriptor)| descriptor),
            "redirectUri",
        )?,
    )?;
    let mut fields = vec![("flowId", p(cx, flow, "id")?)];
    if management.is_some() {
        fields.push(("management", V::Bool(true)))
    }
    fields.extend(vec![
        ("accountId", p(cx, flow, "accountId")?),
        ("displayName", p(cx, &url, "host")?),
        (
            "clientId",
            p(
                cx,
                management.map_or(&auth, |(connection, _)| connection),
                "clientId",
            )?,
        ),
        (
            "clientName",
            p(
                cx,
                management.map_or(flow, |(_, descriptor)| descriptor),
                "clientName",
            )?,
        ),
        ("resource", resource.clone()),
        ("deviceId", p(cx, device, "deviceId")?),
        ("deviceEpoch", p(cx, device, "epoch")?),
        ("scopes", p(cx, flow, "scopes")?),
        ("requestDigest", hash),
        (
            "connectionId",
            if let Some((connection, _)) = management {
                p(cx, connection, "id")?
            } else {
                p(cx, flow, "connectionId")?
            },
        ),
        ("callbackOrigin", p(cx, &callback, "origin")?),
    ]);
    if management.is_none() && p(cx, flow, "reuseExisting")?.truthy() {
        fields.extend(vec![
            ("reuseExisting", V::Bool(true)),
            ("recoveryRoots", p(cx, flow, "recoveryRoots")?),
        ])
    }
    Ok(cx.object(fields))
}
fn remove(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let resource = p(cx, input, "resource")?;
    let device = p(cx, input, "device")?;
    let args = p(cx, input, "input")?;
    let owner = p(cx, input, "owner")?;
    let registration = cx.read(format!("device:{}", p(cx, &device, "deviceId")?.text()))?;
    if !registered(cx, &registration, &device)? {
        return fail("Device is no longer registered.", 403);
    }
    let connection = cx.read(account("connection", &p(cx, &args, "connectionId")?))?;
    let device_owner = cx.read(account("device-owner", &p(cx, &device, "deviceId")?))?;
    if !connection.truthy()
        || p(cx, &connection, "accountId")? != p(cx, &owner, "accountId")?
        || p(cx, &connection, "resource")? != resource
        || !device_owner.truthy()
        || p(cx, &device_owner, "accountId")? != p(cx, &owner, "accountId")?
        || p(cx, &device_owner, "epoch")? != p(cx, &device, "epoch")?
    {
        return fail(
            "Removal does not belong to this device and connection.",
            403,
        );
    }
    let saved = cx.read(key("removal", &p(cx, &args, "requestId")?))?;
    if saved.truthy() {
        if p(cx, &saved, "fingerprint")? != p(cx, input, "fingerprint")? {
            return fail("Removal request changed.", 409);
        }
        return p(cx, &saved, "result");
    }
    let mut targets = vec![];
    let shares = cx.array(&p(cx, &connection, "shares")?)?;
    for share in &shares {
        if p(cx, share, "deviceId")? == p(cx, &device, "deviceId")?
            && p(cx, share, "deviceEpoch")? == p(cx, &device, "epoch")?
            && contains(cx, &p(cx, &args, "rootIds")?, &p(cx, share, "rootId")?)?
        {
            targets.push(share.clone())
        }
    }
    if !p(cx, &connection, "revoked")?.truthy()
        && !targets.is_empty()
        && p(cx, &connection, "revision")? != p(cx, &args, "expectedRevision")?
    {
        return fail(
            "Shared scope changed after review; local access remains revoked.",
            409,
        );
    }
    if cx.rows(&key("removal", &V::str("")), 513)?.len() >= 512 {
        return fail("Removal receipt capacity reached.", 429);
    }
    if !targets.is_empty() {
        let kept = cx.list(
            shares
                .into_iter()
                .filter(|s| !targets.contains(s))
                .collect(),
        );
        cx.set(&connection, "shares", kept)?;
        cx.set(
            &connection,
            "revision",
            V::num(numeric(&p(cx, &connection, "revision")?)? + 1.0),
        )?;
        cx.put(
            account("connection", &p(cx, &connection, "id")?),
            connection.clone(),
        )?;
        let link = cx.object(vec![
            ("deviceEpoch", p(cx, &device, "epoch")?),
            ("connectionEpoch", p(cx, &connection, "epoch")?),
        ]);
        cx.put(
            key(
                "device-link",
                &V::str(&format!(
                    "{}:{}",
                    p(cx, &device, "deviceId")?.text(),
                    p(cx, &connection, "id")?.text()
                )),
            ),
            link,
        )?;
    }
    let result = cx.object(vec![
        ("requestId", p(cx, &args, "requestId")?),
        ("connectionId", p(cx, &connection, "id")?),
        ("rootIds", p(cx, &args, "rootIds")?),
        ("removed", V::Bool(true)),
        ("revision", p(cx, &connection, "revision")?),
        ("filesDeleted", V::Bool(false)),
    ]);
    let record = cx.object(vec![
        ("fingerprint", p(cx, input, "fingerprint")?),
        ("result", result.clone()),
    ]);
    cx.put(key("removal", &p(cx, &args, "requestId")?), record)?;
    Ok(result)
}
fn manage(cx: &mut Context<'_>, input: &V) -> Result<V> {
    let resource = p(cx, input, "resource")?;
    let device = p(cx, input, "device")?;
    let args = p(cx, input, "input")?;
    let owner = p(cx, input, "owner")?;
    let action = p(cx, input, "action")?;
    let session = p(cx, input, "sessionHash")?;
    let registration = cx.read(format!("device:{}", p(cx, &device, "deviceId")?.text()))?;
    if !registered(cx, &registration, &device)? {
        return fail("Device registration is unavailable.", 403);
    }
    let ids = cx.read(account("connection-index", &p(cx, &owner, "accountId")?))?;
    let mut connections = vec![];
    for id in array_or_empty(cx, &ids)? {
        let connection = cx.read(account("connection", &id))?;
        if !connection.truthy()
            || p(cx, &connection, "revoked")?.truthy()
            || p(cx, &connection, "accountId")? != p(cx, &owner, "accountId")?
            || p(cx, &connection, "resource")? != resource
        {
            continue;
        }
        let mut roots = vec![];
        for share in cx.array(&p(cx, &connection, "shares")?)? {
            if p(cx, &share, "deviceId")? == p(cx, &device, "deviceId")?
                && p(cx, &share, "deviceEpoch")? == p(cx, &device, "epoch")?
            {
                roots.push(cx.object(vec![
                    ("rootId", p(cx, &share, "rootId")?),
                    ("mode", p(cx, &share, "mode")?),
                ]))
            }
        }
        let membership = cx.read(key(
            "device-link",
            &V::str(&format!(
                "{}:{}",
                p(cx, &device, "deviceId")?.text(),
                id.text()
            )),
        ))?;
        if roots.is_empty()
            && !(cx.get(&membership, "deviceEpoch") == p(cx, &device, "epoch")?
                && p(cx, &membership, "connectionEpoch")? == p(cx, &connection, "epoch")?)
        {
            continue;
        }
        let descriptor = cx.read(key("client", &id))?;
        if !cx.get(&descriptor, "redirectUri").truthy() {
            continue;
        }
        connections.push((connection, roots, descriptor));
    }
    if action.is("connections") {
        let mut result = vec![];
        for (c, roots, d) in connections {
            let url = cx.compute("parseUrl", p(cx, &d, "redirectUri")?)?;
            let roots = cx.list(roots);
            result.push(cx.object(vec![
                ("connectionId", p(cx, &c, "id")?),
                ("revision", p(cx, &c, "revision")?),
                ("clientId", p(cx, &c, "clientId")?),
                ("clientName", p(cx, &d, "clientName")?),
                ("callbackOrigin", p(cx, &url, "origin")?),
                ("scopes", p(cx, &c, "scopes")?),
                ("roots", roots),
            ]));
        }
        let result = cx.list(result);
        return Ok(cx.object(vec![("connections", result)]));
    }
    let Some((connection, _, descriptor)) = connections
        .into_iter()
        .find(|(c, _, _)| cx.get(c, "id") == cx.get(&args, "connectionId"))
    else {
        return fail(
            "This computer is not shared with the selected connection.",
            403,
        );
    };
    let id = p(cx, &args, "flowId")?;
    let mut flow = cx.read(key("flow", &id))?;
    if flow.truthy() {
        let bound = p(cx, &flow, "device")?;
        if !p(cx, &flow, "manageExisting")?.truthy()
            || p(cx, &flow, "connectionId")? != p(cx, &connection, "id")?
            || ["deviceId", "epoch", "keyHash"]
                .iter()
                .any(|k| cx.get(&bound, k) != cx.get(&device, k))
            || p(cx, &bound, "sessionHash")? != session
        {
            return fail("Folder-management intent changed.", 409);
        }
        assert_flow(cx, &resource, &flow)?;
    } else {
        cleanup(
            cx,
            "flow",
            201,
            200,
            "until",
            "Too many pending management requests.",
        )?;
        let actor = cx.spread(
            &p(cx, &owner, "actor")?,
            vec![("sessionBinding", session.clone())],
        )?;
        let auth = cx.object(vec![
            ("clientId", p(cx, &connection, "clientId")?),
            ("scope", p(cx, &connection, "scopes")?),
            ("redirectUri", p(cx, &descriptor, "redirectUri")?),
        ]);
        let bound = cx.spread(&device, vec![("sessionHash", session)])?;
        let created = cx.now()?;
        let until = cx.now()? + 86400000.0;
        flow = cx.object(vec![
            ("id", id.clone()),
            ("mode", V::str("manage")),
            ("manageExisting", V::Bool(true)),
            ("resource", resource.clone()),
            ("accountId", p(cx, &owner, "accountId")?),
            ("actor", actor),
            ("authRequest", auth),
            ("clientName", p(cx, &descriptor, "clientName")?),
            ("scopes", p(cx, &connection, "scopes")?),
            ("connectionId", p(cx, &connection, "id")?),
            ("recoveryEpoch", p(cx, &connection, "epoch")?),
            ("recoveryRevision", p(cx, &connection, "revision")?),
            ("device", bound),
            ("createdAt", V::num(created)),
            ("until", V::num(until)),
            ("finishTaken", V::Bool(false)),
        ]);
        cx.put(key("flow", &id), flow.clone())?;
    }
    native_view(
        cx,
        &resource,
        &flow,
        &device,
        Some((&connection, &descriptor)),
    )
}
