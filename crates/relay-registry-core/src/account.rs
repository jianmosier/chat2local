use crate::common::{array_or_empty, client, grant, numeric, p, resource, scopes, shares};
use crate::{Context, Result, Stop, V, fail};
fn key(kind: &str, id: &V) -> String {
    format!("accounts:v3:{kind}:{}", id.text())
}
fn receipt(cx: &mut Context<'_>, intent: &V) -> Result<V> {
    let mut fields = vec![("version", V::num(1.0))];
    for (out, name) in [
        ("intentId", "id"),
        ("accountId", "accountId"),
        ("connectionId", "connectionId"),
        ("deviceId", "deviceId"),
        ("deviceEpoch", "deviceEpoch"),
        ("snapshotDigest", "snapshotDigest"),
        ("policyDigest", "policyDigest"),
        ("requestDigest", "requestDigest"),
        ("clientId", "clientId"),
        ("resource", "resource"),
        ("roots", "roots"),
        ("scopes", "scopes"),
        ("phase", "phase"),
    ] {
        fields.push((out, p(cx, intent, name)?));
    }
    Ok(cx.object(fields))
}
fn retained(cx: &Context<'_>, connection: &V, intent: &V) -> Result<bool> {
    if !connection.truthy()
        || p(cx, connection, "revoked")?.truthy()
        || p(cx, connection, "epoch")? != p(cx, intent, "connectionEpoch")?
    {
        return Ok(false);
    }
    let roots = cx.array(&p(cx, intent, "roots")?)?;
    let values = cx.array(&p(cx, connection, "shares")?)?;
    for root in roots {
        let mut found = false;
        for share in &values {
            if p(cx, share, "intentId")? == p(cx, intent, "id")?
                && p(cx, share, "deviceId")? == p(cx, intent, "deviceId")?
                && p(cx, share, "rootId")? == p(cx, &root, "rootId")?
                && p(cx, share, "mode")? == p(cx, &root, "mode")?
            {
                found = true;
                break;
            }
        }
        if !found {
            return Ok(false);
        }
    }
    Ok(true)
}
pub fn execute(cx: &mut Context<'_>, op: &str, args: &V) -> Result<V> {
    if op == "account.resolve" {
        return resolve(cx, &p(cx, args, "grant")?);
    }
    let command = p(cx, args, "command")?;
    let action = p(cx, &command, "action")?;
    let actor = p(cx, &command, "actor")?;
    let input = p(cx, &command, "input")?;
    let native = p(cx, args, "native")?;
    cx.branch = action.text();
    let guard = p(cx, args, "guard")?;
    match cx.get(&guard, "kind").text().as_str() {
        "none" => {}
        "activeSession" => crate::common::active_session(cx, &actor)?,
        "instanceFlow" => {
            crate::instance::assert_flow(cx, &p(cx, &guard, "resource")?, &p(cx, &guard, "flow")?)?
        }
        _ => return Err(Stop::Invalid),
    }
    let identity = p(cx, &actor, "identityKey")?;
    let binding = p(cx, &actor, "sessionBinding")?;
    let mut account = cx.read(key("identity", &identity))?;
    cx.branch = action.text();
    if !account.truthy() {
        if !action.is("account") {
            return fail("Account has not been established.", 401);
        }
        cx.exact(&input, &[])?;
        let id = cx.random("id")?;
        let now = cx.now()?;
        account = cx.object(vec![("id", id), ("createdAt", V::num(now))]);
        cx.put(key("identity", &identity), account.clone())?;
    }
    let account_id = p(cx, &account, "id")?;
    if !account_id.hex(32) {
        return Err(Stop::Invalid);
    }
    if action.is("account") {
        cx.exact(&input, &[])?;
        return Ok(cx.object(vec![("accountId", account_id)]));
    }
    if action.is("connections") {
        let requested = p(cx, &input, "clientId")?;
        cx.exact(
            &input,
            if requested == V::Undefined {
                &["resource"]
            } else {
                &["clientId", "resource"]
            },
        )?;
        let wanted = if requested == V::Undefined {
            V::Null
        } else {
            client(&requested)?
        };
        let r = resource(cx, &p(cx, &input, "resource")?)?;
        let index = cx.read(key("connection-index", &account_id))?;
        let mut found = vec![];
        for id in array_or_empty(cx, &index)? {
            let item = cx.read(key("connection", &id))?;
            if item.truthy()
                && !p(cx, &item, "revoked")?.truthy()
                && p(cx, &item, "accountId")? == account_id
                && (!wanted.truthy() || p(cx, &item, "clientId")? == wanted)
                && p(cx, &item, "resource")? == r
            {
                found.push(cx.object(vec![
                    ("connectionId", p(cx, &item, "id")?),
                    ("clientId", p(cx, &item, "clientId")?),
                    ("scopes", p(cx, &item, "scopes")?),
                ]));
            }
        }
        let list = cx.list(found);
        return Ok(cx.object(vec![("accountId", account_id), ("connections", list)]));
    }
    if action.is("prepare") {
        return prepare(cx, &account_id, &binding, &input);
    }
    if action.is("revoke-share") || action.is("revoke-connection") {
        return revoke(cx, &account_id, &action, &input);
    }
    if !action.is("confirm") && !action.is("activate") {
        cx.exact(&input, &["intentId"])?
    }
    let id = p(cx, &input, "intentId")?;
    if !id.hex(32) {
        return fail("Invalid consent ID.", 400);
    }
    let intent = cx.read(key("intent", &id))?;
    if !intent.truthy() || p(cx, &intent, "accountId")? != account_id {
        return fail("Unknown consent for this account.", 404);
    }
    let phase = p(cx, &intent, "phase")?;
    if action.is("status") {
        if phase.is("active") {
            let live = cx.read(key("connection", &p(cx, &intent, "connectionId")?))?;
            let keep = retained(cx, &live, &intent)?;
            if keep {
                cx.branch = "status-active".into();
                return receipt(cx, &intent);
            }
            cx.branch = "status-revoked".into();
            let v = cx.spread(&intent, vec![("phase", V::str("revoked"))])?;
            return receipt(cx, &v);
        }
        let expiry = p(
            cx,
            &intent,
            if phase.is("prepared") {
                "expiresAt"
            } else {
                "resumeUntil"
            },
        )?;
        let now = cx.now()?;
        let expired = if phase.is("cancelled") {
            false
        } else {
            now > numeric(&expiry)?
        };
        if expired && !phase.is("cancelled") {
            cx.branch = "status-expired".into();
            let v = cx.spread(&intent, vec![("phase", V::str("expired"))])?;
            return receipt(cx, &v);
        }
        return receipt(cx, &intent);
    }
    if action.is("cancel") {
        if phase.is("active") {
            return fail("Use explicit share revocation after activation.", 409);
        }
        cx.set(&intent, "phase", V::str("cancelled"))?;
        cx.put(key("intent", &p(cx, &intent, "id")?), intent.clone())?;
        return receipt(cx, &intent);
    }
    if phase.is("cancelled") {
        return fail("Consent cancelled; it cannot be replayed.", 409);
    }
    if p(cx, &intent, "snapshotDigest")? != p(cx, &input, "snapshotDigest")?
        || p(cx, &native, "snapshotDigest")? != p(cx, &intent, "snapshotDigest")?
    {
        return fail("Consent snapshot changed.", 403);
    }
    if p(cx, &native, "intentId")? != p(cx, &intent, "id")?
        || p(cx, &native, "deviceId")? != p(cx, &intent, "deviceId")?
        || p(cx, &native, "deviceEpoch")? != p(cx, &intent, "deviceEpoch")?
        || !p(cx, &native, "phase")?.is(if action.is("confirm") {
            "consented"
        } else {
            "activated"
        })
    {
        return fail("Native receipt no longer matches current consent.", 403);
    }
    if action.is("confirm") && binding != p(cx, &intent, "sessionBinding")? {
        return fail("Account session changed; stale page cannot confirm.", 403);
    }
    let connection = cx.read(key("connection", &p(cx, &intent, "connectionId")?))?;
    if phase.is("active") {
        if !retained(cx, &connection, &intent)? {
            return fail("Previously activated share has been revoked.", 409);
        }
        cx.branch = if action.is("confirm") {
            "active-idempotent-confirm"
        } else {
            "active-idempotent-activate"
        }
        .into();
        let g = grant(cx, &connection, p(cx, &intent, "scopes")?)?;
        let r = receipt(cx, &intent)?;
        return cx.spread(&r, vec![("grant", g)]);
    }
    if cx.now()?
        > numeric(&p(
            cx,
            &intent,
            if phase.is("prepared") {
                "expiresAt"
            } else {
                "resumeUntil"
            },
        )?)?
    {
        return fail("Consent expired. No share granted.", 409);
    }
    let old_revision = cx.get(&connection, "revision");
    let revision = if old_revision.truthy() {
        old_revision
    } else {
        V::num(0.0)
    };
    if revision != p(cx, &intent, "connectionRevision")? || cx.get(&connection, "revoked").truthy()
    {
        return fail("Connection changed after the displayed consent.", 409);
    }
    let owner = cx.read(key("device-owner", &p(cx, &intent, "deviceId")?))?;
    if owner.truthy()
        && (p(cx, &owner, "accountId")? != account_id
            || p(cx, &owner, "epoch")? != p(cx, &intent, "deviceEpoch")?)
    {
        return fail("Device belongs to another account or epoch.", 403);
    }
    if action.is("confirm") {
        if phase.is("prepared") {
            cx.branch = "confirm-prepared".into();
            cx.set(&intent, "phase", V::str("consented"))?;
            let now = cx.now()?;
            cx.set(&intent, "consentedAt", V::num(now))?;
            let until = cx.now()? + 86400000.0;
            cx.set(&intent, "resumeUntil", V::num(until))?;
            cx.put(key("intent", &p(cx, &intent, "id")?), intent.clone())?;
        }
        return receipt(cx, &intent);
    }
    if !phase.is("consented") {
        return fail(
            "A matching explicit consent is required before activation.",
            403,
        );
    }
    let index_value = cx.read(key("connection-index", &account_id))?;
    let mut index = array_or_empty(cx, &index_value)?;
    if !connection.truthy() && index.len() >= 20 {
        return fail("Account connection limit reached.", 429);
    }
    let current = if connection.truthy() {
        connection.clone()
    } else {
        let empty = cx.list(vec![]);
        cx.object(vec![
            ("id", p(cx, &intent, "connectionId")?),
            ("accountId", account_id.clone()),
            ("clientId", p(cx, &intent, "clientId")?),
            ("resource", p(cx, &intent, "resource")?),
            ("epoch", p(cx, &intent, "connectionEpoch")?),
            ("scopes", p(cx, &intent, "scopes")?),
            ("revision", V::num(0.0)),
            ("revoked", V::Bool(false)),
            ("policy", V::str("explicit-shares")),
            ("shares", empty),
        ])
    };
    let roots = cx.array(&p(cx, &intent, "roots")?)?;
    let old = cx.array(&p(cx, &current, "shares")?)?;
    let mut next = vec![];
    for share in old {
        let mut replaced = false;
        if p(cx, &share, "deviceId")? == p(cx, &intent, "deviceId")? {
            for root in &roots {
                if p(cx, root, "rootId")? == p(cx, &share, "rootId")? {
                    replaced = true;
                    break;
                }
            }
        }
        if !replaced {
            next.push(share)
        }
    }
    for root in roots {
        next.push(cx.spread(
            &root,
            vec![
                ("deviceId", p(cx, &intent, "deviceId")?),
                ("deviceEpoch", p(cx, &intent, "deviceEpoch")?),
                ("intentId", p(cx, &intent, "id")?),
            ],
        )?);
    }
    let mut distinct = vec![];
    for share in &next {
        let d = p(cx, share, "deviceId")?;
        if !distinct.contains(&d) {
            distinct.push(d)
        }
    }
    if distinct.len() > 20 || next.len() > 100 {
        return fail("Connection share limit reached.", 429);
    }
    if p(cx, &intent, "allowScopeUpgrade")? == V::Bool(true) {
        let mut union = cx.array(&p(cx, &current, "scopes")?)?;
        for scope in cx.array(&p(cx, &intent, "scopes")?)? {
            if !union.contains(&scope) {
                union.push(scope)
            }
        }
        let input = cx.list(union);
        let selected = scopes(cx, &input)?;
        cx.set(&current, "scopes", selected)?;
    }
    let next = cx.list(next);
    cx.set(&current, "shares", next)?;
    cx.set(
        &current,
        "revision",
        V::num(numeric(&p(cx, &current, "revision")?)? + 1.0),
    )?;
    let owner = cx.object(vec![
        ("accountId", account_id.clone()),
        ("epoch", p(cx, &intent, "deviceEpoch")?),
    ]);
    cx.put(key("device-owner", &p(cx, &intent, "deviceId")?), owner)?;
    cx.put(key("connection", &p(cx, &current, "id")?), current.clone())?;
    if !connection.truthy() {
        index.push(p(cx, &current, "id")?);
        let value = cx.list(index);
        cx.put(key("connection-index", &account_id), value)?;
    }
    cx.set(&intent, "phase", V::str("active"))?;
    cx.put(key("intent", &p(cx, &intent, "id")?), intent.clone())?;
    let g = grant(cx, &current, p(cx, &intent, "scopes")?)?;
    let r = receipt(cx, &intent)?;
    cx.spread(&r, vec![("grant", g)])
}
fn prepare(cx: &mut Context<'_>, account: &V, binding: &V, input: &V) -> Result<V> {
    cx.exact(
        input,
        &[
            "intentId",
            "connectionId",
            "clientId",
            "resource",
            "deviceId",
            "deviceEpoch",
            "roots",
            "scopes",
            "policyDigest",
            "requestDigest",
            "allowScopeUpgrade",
        ],
    )?;
    let upgrade = p(cx, input, "allowScopeUpgrade")?;
    if !matches!(upgrade, V::Undefined | V::Bool(_)) {
        return fail("Invalid server authorization context.", 400);
    }
    let id = p(cx, input, "intentId")?;
    let requested_connection = p(cx, input, "connectionId")?;
    if !id.hex(32)
        || (requested_connection != V::Null && !requested_connection.hex(32))
        || !p(cx, input, "deviceId")?.hex(32)
        || !["deviceEpoch", "policyDigest", "requestDigest"]
            .iter()
            .all(|k| cx.get(input, k).hex(64))
    {
        return fail("Invalid immutable consent snapshot.", 400);
    }
    let roots = shares(cx, &p(cx, input, "roots")?)?;
    let selected_scopes = scopes(cx, &p(cx, input, "scopes")?)?;
    let selected_client = client(&p(cx, input, "clientId")?)?;
    let selected_resource = resource(cx, &p(cx, input, "resource")?)?;
    let scopes_array = cx.array(&selected_scopes)?;
    for root in cx.array(&roots)? {
        let mode = p(cx, &root, "mode")?;
        if mode.is("direct") && !scopes_array.iter().any(|s| s.is("files:write")) {
            return fail("Direct sharing was not requested by this client.", 400);
        }
        if mode.is("review") && !scopes_array.iter().any(|s| s.is("files:propose")) {
            return fail("Review sharing was not requested by this client.", 400);
        }
    }
    let request = cx.spread(
        input,
        vec![
            ("roots", roots),
            ("scopes", selected_scopes.clone()),
            ("clientId", selected_client.clone()),
            ("resource", selected_resource.clone()),
        ],
    )?;
    let request_hash = cx.compute("jsonSha256", request.clone())?;
    let previous = cx.read(key("intent", &id))?;
    if previous.truthy() {
        if p(cx, &previous, "accountId")? != *account
            || p(cx, &previous, "sessionBinding")? != *binding
            || p(cx, &previous, "requestHash")? != request_hash
            || p(cx, &previous, "phase")?.is("cancelled")
        {
            return fail("Consent ID cannot be reused for another request.", 409);
        }
        cx.branch = "prepare-idempotent".into();
        return receipt(cx, &previous);
    }
    let connection = if requested_connection.truthy() {
        cx.read(key("connection", &requested_connection))?
    } else {
        V::Null
    };
    if requested_connection.truthy()
        && (!connection.truthy()
            || p(cx, &connection, "accountId")? != *account
            || p(cx, &connection, "clientId")? != selected_client
            || p(cx, &connection, "resource")? != selected_resource
            || p(cx, &connection, "revoked")?.truthy())
    {
        return fail(
            "Connection does not belong to this account/client/resource.",
            403,
        );
    }
    if connection.truthy() {
        let ceiling = cx.array(&p(cx, &connection, "scopes")?)?;
        if scopes_array.iter().any(|s| !ceiling.contains(s)) && upgrade != V::Bool(true) {
            return fail(
                "A new OAuth permission requires explicit connection reauthorization.",
                403,
            );
        }
    }
    let owner = cx.read(key("device-owner", &p(cx, input, "deviceId")?))?;
    if owner.truthy()
        && (p(cx, &owner, "accountId")? != *account
            || p(cx, &owner, "epoch")? != p(cx, input, "deviceEpoch")?)
    {
        return fail("Device ownership does not match.", 403);
    }
    let all = cx.read(key("intent-index", account))?;
    let mut index = vec![];
    for item in array_or_empty(cx, &all)? {
        if item == V::Hole {
            continue;
        }
        if numeric(&p(cx, &item, "until")?)? > cx.now()? {
            index.push(item)
        }
    }
    if index.len() >= 32 {
        return fail("Too many account setup attempts.", 429);
    }
    let existing_id = cx.get(&connection, "id");
    let connection_id = if existing_id.truthy() {
        existing_id
    } else {
        cx.random("id")?
    };
    let old_epoch = cx.get(&connection, "epoch");
    let epoch = if old_epoch.truthy() {
        old_epoch
    } else {
        cx.random("secret")?
    };
    let old_revision = cx.get(&connection, "revision");
    let revision = if old_revision.truthy() {
        old_revision
    } else {
        V::num(0.0)
    };
    let expires = cx.now()? + 300000.0;
    let intent = cx.spread(
        &request,
        vec![
            ("id", id.clone()),
            ("accountId", account.clone()),
            ("sessionBinding", binding.clone()),
            ("requestHash", request_hash.clone()),
            ("connectionId", connection_id.clone()),
            ("connectionEpoch", epoch.clone()),
            ("connectionRevision", revision.clone()),
            ("phase", V::str("prepared")),
            ("expiresAt", V::num(expires)),
        ],
    )?;
    let snapshot = cx.object(vec![
        ("accountId", account.clone()),
        ("connectionId", connection_id),
        ("connectionEpoch", epoch),
        ("connectionRevision", revision),
        ("requestHash", request_hash),
        ("sessionBinding", binding.clone()),
    ]);
    let digest = cx.compute("jsonSha256", snapshot)?;
    cx.set(&intent, "snapshotDigest", digest)?;
    cx.put(key("intent", &id), intent.clone())?;
    let until = cx.now()? + 86400000.0;
    let entry = cx.object(vec![("id", id.clone()), ("until", V::num(until))]);
    let mut updated = index.clone();
    updated.push(entry);
    let value = cx.list(updated);
    cx.put(key("intent-index", account), value)?;
    let cleanup = cx.read(key("cleanup-index", account))?;
    for old in array_or_empty(cx, &cleanup)? {
        if numeric(&p(cx, &old, "until")?)? <= cx.now()? {
            cx.delete(key("intent", &p(cx, &old, "id")?))?
        }
    }
    let until = cx.now()? + 86400000.0;
    let entry = cx.object(vec![("id", id), ("until", V::num(until))]);
    index.push(entry);
    let value = cx.list(index);
    cx.put(key("cleanup-index", account), value)?;
    receipt(cx, &intent)
}
fn resolve(cx: &mut Context<'_>, grant: &V) -> Result<V> {
    cx.branch = "resolved".into();
    let connection = cx.read(key("connection", &p(cx, grant, "connectionId")?))?;
    if !connection.truthy()
        || p(cx, &connection, "revoked")?.truthy()
        || p(cx, &connection, "accountId")? != p(cx, grant, "accountId")?
        || p(cx, &connection, "epoch")? != p(cx, grant, "connectionEpoch")?
        || p(cx, &connection, "clientId")? != p(cx, grant, "clientId")?
        || p(cx, &connection, "resource")? != p(cx, grant, "resource")?
        || !p(cx, &connection, "policy")?.is("explicit-shares")
    {
        return fail(
            "Account connection is revoked or does not match this grant.",
            403,
        );
    }
    let ceiling = cx.array(&p(cx, &connection, "scopes")?)?;
    let selected: Vec<V> = cx
        .array(&p(cx, grant, "scopes")?)?
        .into_iter()
        .filter(|s| ceiling.contains(s))
        .collect();
    if !selected.iter().any(|s| s.is("files:read")) {
        return fail("Read scope is required.", 403);
    }
    let mut groups: Vec<(V, V, Vec<V>)> = vec![];
    for share in cx.array(&p(cx, &connection, "shares")?)? {
        let id = p(cx, &share, "deviceId")?;
        let owner = cx.read(key("device-owner", &id))?;
        if !owner.truthy()
            || p(cx, &owner, "accountId")? != p(cx, grant, "accountId")?
            || p(cx, &owner, "epoch")? != p(cx, &share, "deviceEpoch")?
        {
            continue;
        }
        let root = cx.object(vec![
            ("rootId", p(cx, &share, "rootId")?),
            ("mode", p(cx, &share, "mode")?),
        ]);
        if let Some((_, _, roots)) = groups.iter_mut().find(|(d, _, _)| *d == id) {
            roots.push(root)
        } else {
            groups.push((id, p(cx, &share, "deviceEpoch")?, vec![root]))
        }
    }
    let mut devices = vec![];
    for (id, epoch, roots) in groups {
        let roots = cx.list(roots);
        devices.push(cx.object(vec![("deviceId", id), ("epoch", epoch), ("roots", roots)]));
    }
    let devices = cx.list(devices);
    let selected = cx.list(selected);
    Ok(cx.object(vec![
        ("connectionId", p(cx, &connection, "id")?),
        ("accountId", p(cx, &connection, "accountId")?),
        ("clientId", p(cx, &connection, "clientId")?),
        ("resource", p(cx, &connection, "resource")?),
        ("scopes", selected),
        ("revision", p(cx, &connection, "revision")?),
        ("devices", devices),
    ]))
}
fn revoke(cx: &mut Context<'_>, account: &V, action: &V, input: &V) -> Result<V> {
    cx.exact(
        input,
        if action.is("revoke-connection") {
            &["connectionId"]
        } else {
            &["connectionId", "deviceId", "rootId"]
        },
    )?;
    let id = p(cx, input, "connectionId")?;
    if !id.hex(32) {
        return fail("Invalid connection ID.", 400);
    }
    let connection = cx.read(key("connection", &id))?;
    if !connection.truthy() || p(cx, &connection, "accountId")? != *account {
        return fail("Connection does not belong to this account.", 403);
    }
    if action.is("revoke-connection") {
        cx.set(&connection, "revoked", V::Bool(true))?;
        let epoch = cx.random("secret")?;
        cx.set(&connection, "epoch", epoch)?;
    } else {
        let row = cx.object(vec![
            ("rootId", p(cx, input, "rootId")?),
            ("mode", V::str("read-only")),
        ]);
        let rows = cx.list(vec![row]);
        shares(cx, &rows)?;
        let device = p(cx, input, "deviceId")?;
        if !device.hex(32) {
            return fail("Invalid device ID.", 400);
        }
        let mut kept = vec![];
        for share in cx.array(&p(cx, &connection, "shares")?)? {
            if p(cx, &share, "deviceId")? != device
                || p(cx, &share, "rootId")? != p(cx, input, "rootId")?
            {
                kept.push(share)
            }
        }
        let value = cx.list(kept);
        cx.set(&connection, "shares", value)?;
    }
    let revision = V::num(numeric(&p(cx, &connection, "revision")?)? + 1.0);
    cx.set(&connection, "revision", revision.clone())?;
    cx.put(key("connection", &p(cx, &connection, "id")?), connection)?;
    Ok(cx.object(vec![("revoked", V::Bool(true)), ("revision", revision)]))
}
