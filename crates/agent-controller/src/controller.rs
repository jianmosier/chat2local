use crate::{
    Error, ROUTES, Reply, Request, Result,
    persistence::confirmed,
    root_mode,
    runtime::{Host, State},
    value,
};
use chat2local_js_value_compat::{Document, Value};
use serde_json::json;
use std::sync::{Arc, atomic::Ordering};

pub fn binding(state: &State, origin: &str) -> Result<String> {
    let mut out = value::parse(b"[]")?;
    let root = out.root();
    let origin = out.add(value::text(origin), usize::MAX)?;
    out.push(root, origin)?;
    let id = value::prop(&state.config, "installationId")
        .ok_or_else(|| Error::new(400, "Missing installation identity."))?;
    let id = out.import(
        value::parse(value::subtree(&state.config, id)?.as_bytes())?,
        usize::MAX,
    )?;
    out.push(root, id)?;
    let identity = value::prop(&state.secrets, "identity");
    for key in ["origin", "deviceId", "deviceKey"] {
        let id = identity.and_then(|i| value::get(&state.secrets, i, key));
        let doc = if value::truthy(&state.secrets, id) {
            value::parse(value::subtree(&state.secrets, id.unwrap())?.as_bytes())?
        } else {
            value::parse(b"\"\"")?
        };
        let id = out.import(doc, usize::MAX)?;
        out.push(root, id)?;
    }
    value::serialized(&out)
}
async fn authenticate(host: &Arc<Host>, request: &Request) -> Result<bool> {
    if request.header("host") != host.origin.strip_prefix("http://").unwrap() {
        return Err(Error::new(403, "Invalid Host."));
    }
    if !request.header("origin").is_empty() && request.header("origin") != host.origin {
        return Err(Error::new(403, "Invalid Origin."));
    }
    let navigation = request.method == "GET"
        && ["/connect", "/account-connect", "/instance-connect"].contains(&request.target.as_str())
        && request.header("sec-fetch-mode") == "navigate"
        && request.header("sec-fetch-dest") == "document";
    if request.header("sec-fetch-site") == "cross-site" && !navigation {
        return Err(Error::new(403, "Cross-site access is not allowed."));
    }
    if !request.target.starts_with('/')
        || request.target.starts_with("//")
        || request.target.contains('?')
    {
        return Err(Error::new(400, "Invalid request target."));
    }
    let token = request.header("x-chat2local-token");
    let launcher = token.len() == 64
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && openssl::memcmp::eq(token.as_bytes(), host.token.as_bytes());
    let manager_route = (request.method == "GET" && request.target == "/api/status")
        || (request.method == "POST"
            && [
                "/api/management/session",
                "/api/management/logout",
                "/api/management/startup",
                "/api/folder/browse",
                "/api/shares/connections",
                "/api/shares/prepare",
                "/api/shares/confirm",
                "/api/shares/status",
                "/api/shares/resume",
                "/api/shares/remove-prepare",
                "/api/shares/remove-confirm",
                "/api/shares/removals",
                "/api/terminal/permissions",
                "/api/terminal/set-permission",
            ]
            .contains(&request.target.as_str()));
    if request.target.starts_with("/api/") && !launcher {
        if !manager_route || request.header("x-chat2local-manager") != "1" {
            return Err(Error::new(401, "Local control session required."));
        }
        let binding = binding(&host.lock_state(), &host.origin)?;
        let slot = host
            .authentication
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::new(429, "Authentication capacity reached."))?;
        let owner = host.clone();
        let cookie = request.header("cookie").to_owned();
        let matched = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            owner
                .sessions
                .lock()
                .unwrap()
                .matching(&owner.store, &binding, &cookie)
                .map(|v| v.is_some())
        })
        .await
        .map_err(|_| Error::new(503, "Management verification failed."))??;
        if !matched {
            return Err(Error::new(401, "Local control session required."));
        }
    }
    Ok(launcher)
}
fn status(host: &Host) -> Result<Reply> {
    let snapshot = if host.faulted() {
        None
    } else {
        Some(host.command(json!({"op":"snapshot"}))?)
    };
    let mut state = host.lock_state();
    let (pending, events) = crate::operations::projection(&mut state)?;
    let mut status = value::parse(crate::version().to_string().as_bytes())?;
    for key in ["paused", "startup", "relay", "installationId"] {
        if let Some(id) = value::prop(&state.config, key) {
            let id = status.import(
                value::parse(value::subtree(&state.config, id)?.as_bytes())?,
                usize::MAX,
            )?;
            status.set_property(status.root(), key.encode_utf16().collect(), id)?;
        }
    }
    for key in ["roots", "accountRoots"] {
        let mut items = Vec::new();
        for id in value::array(&state.config, value::prop(&state.config, key)).unwrap_or_default() {
            let mut item = value::parse(value::subtree(&state.config, id)?.as_bytes())?;
            value::put(
                &mut item,
                "writeMode",
                value::text(&root_mode(&state.config, id)?),
            )?;
            if key == "accountRoots" {
                value::put(&mut item, "accountScoped", Value::Bool(true))?;
            }
            items.push(status.import(item, usize::MAX)?);
        }
        value::put(&mut status, key, Value::Array(items))?;
    }
    if host.faulted() {
        value::put(&mut status, "paused", Value::Bool(true))?;
    }
    value::put(&mut status, "instanceId", value::text(&host.instance))?;
    let bridge = if host.faulted() {
        "failed"
    } else if value::prop(&state.secrets, "identity").is_some()
        && crate::tools::identity(&state.secrets).is_err()
    {
        "unavailable"
    } else {
        snapshot
            .as_ref()
            .and_then(|s| s["result"]["bridge"]["state"].as_str())
            .unwrap_or("not-configured")
    };
    value::put(&mut status, "bridge", value::text(bridge))?;
    value::put(
        &mut status,
        "queuedOperations",
        Value::Number(host.pending() as f64),
    )?;
    value::put(
        &mut status,
        "pendingPersistence",
        Value::Number(host.persistence.pending() as f64),
    )?;
    value::put(
        &mut status,
        "terminalJobsRunning",
        Value::Number(host.terminal.active() as f64),
    )?;
    value::put(
        &mut status,
        "terminalAvailable",
        Value::Bool(host.terminal.available()),
    )?;
    value::put(
        &mut status,
        "pendingTerminalPersistence",
        Value::Number(host.terminal.journal.pending() as f64),
    )?;
    value::put(
        &mut status,
        "startupAvailable",
        Value::Bool(crate::native::startup_eligible(
            host.store.directory(),
            &host.origin,
        )),
    )?;
    value::put(
        &mut status,
        "folderPickerActive",
        Value::Bool(host.platform.picker_active()),
    )?;
    value::put(&mut status, "upgradeReady", Value::Bool(false))?;
    value::put(&mut status, "nativeFault", Value::Bool(host.faulted()))?;
    value::put(
        &mut status,
        "setupActive",
        Value::Bool(host.workflows.setup_active()),
    )?;
    value::put(
        &mut status,
        "mcpUrl",
        crate::tools::identity(&state.secrets)
            .ok()
            .map_or(Value::Null, |i| value::text(&format!("{}/mcp", i.origin))),
    )?;
    let setup = value::parse(host.workflows.inner.lock().unwrap().setup_info.as_bytes())?;
    let setup = status.import(setup, usize::MAX)?;
    status.set_property(status.root(), "setup".encode_utf16().collect(), setup)?;
    for (key, object) in [
        // Preserve status/recovery on metadata failure. An absent name cannot
        // satisfy the share page's strict automatic-consent comparison.
        ("device", crate::tools::description().unwrap_or_else(|_| json!({}))),
        ("network", host.network.status()),
        (
            "networkSettings",
            serde_json::to_value(crate::network::saved(&state.config)?).unwrap(),
        ),
    ] {
        let id = status.import(value::parse(object.to_string().as_bytes())?, usize::MAX)?;
        status.set_property(status.root(), key.encode_utf16().collect(), id)?;
    }
    for (key, val) in [("pending", pending), ("events", events)] {
        let id = status.import(value::parse(val.to_string().as_bytes())?, usize::MAX)?;
        status.set_property(status.root(), key.encode_utf16().collect(), id)?;
    }
    if host.faulted() {
        value::put(
            &mut status,
            "lifecycleWarning",
            value::text(
                "Native lifecycle failed permanently; only restrictive local recovery is available.",
            ),
        )?;
    }
    for (key, warning) in [
        ("persistenceWarning", &state.persistence_warning),
        ("bridgeWarning", &state.bridge_warning),
        ("guideWarning", &state.guide_warning),
        ("lastRemoteCallAt", &state.last_remote),
    ] {
        if let Some(w) = warning {
            value::put(&mut status, key, value::text(w))?;
        }
    }
    Ok(Reply {
        content_type: "application/json; charset=utf-8",
        status: 200,
        body: value::serialized(&status)?,
        cookie: None,
    })
}
pub async fn execute(host: &Arc<Host>, mut request: Request, recovery: bool) -> Result<Reply> {
    if !host.active.load(Ordering::SeqCst) {
        return Err(Error::new(503, "Controller is closing."));
    }
    let launcher = authenticate(host, &request).await?;
    if let Some(asset) = crate::ui::asset(&request) {
        return Ok(asset);
    }
    if request.target == "/api/status" && request.method == "GET" {
        return status(host);
    }
    let fault = host.faulted();
    if fault && !recovery {
        return Err(Error::new(503, "Ordinary work is frozen."));
    }
    if fault
        && ![
            "/api/pause",
            "/api/root/remove",
            "/api/account-root/remove",
            "/api/shutdown",
        ]
        .contains(&request.target.as_str())
    {
        return Err(Error::new(
            503,
            "Only restrictive local recovery is available.",
        ));
    }
    if !ROUTES.contains(&request.target.as_str()) {
        return Err(Error::new(
            501,
            "Route unavailable in native controller fixture.",
        ));
    }
    if request.target == "/api/guide" && request.method == "GET" {
        return crate::guide::view(host);
    }
    if crate::workflow::route(&request.target) && request.method == "GET" {
        return crate::workflow::execute(host, request, None).await;
    }
    if request.method != "POST" {
        return Err(Error::new(405, "POST required."));
    }
    if request.header("origin") != host.origin {
        return Err(Error::new(403, "Same-origin confirmation required."));
    }
    if !request
        .header("content-type")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/json")
    {
        return Err(Error::new(415, "application/json is required."));
    }
    let input = value::parse(
        request
            .body
            .strip_prefix(&[239, 187, 191])
            .unwrap_or(&request.body),
    )?;
    if crate::workflow::route(&request.target) {
        return crate::workflow::execute(host, request, Some(crate::workflow_value::Doc(input)))
            .await;
    }
    match request.target.as_str() {
        "/api/folder/select" => {
            value::fields(&input, &["write", "writeMode", "confirmDirect"])?;
            crate::consent::permission(&input)?;
            let revision = host.platform.selection_revision();
            let selected = host
                .platform
                .pick(host, request.disconnected.clone())
                .await?;
            let selected = value::parse(selected.body.as_bytes())?;
            let Some(path) = value::string(&selected, value::prop(&selected, "path")) else {
                return Ok(Reply::json(json!({"cancelled":true})));
            };
            let mut input = input;
            value::put(&mut input, "path", value::text(&path))?;
            request.target = "/api/root/add".into();
            request.body = value::serialized(&input)?.into_bytes();
            request.selection = Some(revision);
            let reply = Box::pin(host.dispatch(request)).await;
            return Ok(if reply.status == 409 {
                Reply::json(json!({"cancelled":true}))
            } else {
                reply
            });
        }
        "/api/root/add" | "/api/root/set-mode" | "/api/guide/authorize" | "/api/guide/cancel" => {
            return crate::consent::execute(
                host,
                &request.target,
                input,
                request.disconnected,
                request.selection,
            )
            .await;
        }
        "/api/guide/session-tools" => return crate::guide::session(host, &input),
        "/api/pick-folder" => {
            value::fields(&input, &[])?;
            return host.platform.pick(host, request.disconnected).await;
        }
        "/api/folder/cancel" => {
            value::fields(&input, &[])?;
            host.platform.cancel_picker();
            return Ok(Reply::json(json!({"ok":true})));
        }
        "/api/folder/browse" => return host.platform.browse(host, &input).await,
        "/api/startup" | "/api/management/startup" => {
            return host.platform.startup(host, &input).await;
        }
        _ => {}
    }
    if request.target == "/api/approve" {
        return crate::operations::approve(host, &input)
            .await
            .map(Reply::json);
    }
    if ["/api/network/set", "/api/network/check"].contains(&request.target.as_str()) {
        return crate::network::action(host, &request.target, &input)
            .await
            .map(Reply::json);
    }
    if request.target == "/api/shutdown" {
        value::fields(&input, &[])?;
        host.close();
        return Ok(Reply::json(json!({"ok":true,"accepted":true})));
    }
    if ["/api/management/session", "/api/management/logout"].contains(&request.target.as_str()) {
        value::fields(&input, &[])?;
        let host = host.clone();
        let owner = host.clone();
        let epoch = host.lock_state().epoch;
        let receive = host.persistence.submit(move |store| {
            if owner.faulted() || owner.closing.load(Ordering::SeqCst) {
                return Err(Error::new(503, "Management session mutation is frozen."));
            }
            let binding = binding(&owner.lock_state(), &owner.origin)?;
            let mut sessions = owner.sessions.lock().unwrap();
            if request.target == "/api/management/session" {
                let (expires, cookie) =
                    sessions.establish(store, &binding, request.header("cookie"), launcher)?;
                Ok(Reply {
                    content_type: "application/json; charset=utf-8",
                    status: 200,
                    body: json!({"ready":true,"expiresAt":expires}).to_string(),
                    cookie: Some(cookie),
                })
            } else {
                let cookie = sessions.logout(store, request.header("cookie"))?;
                Ok(Reply {
                    content_type: "application/json; charset=utf-8",
                    status: 200,
                    body: json!({"cleared":true}).to_string(),
                    cookie: Some(cookie),
                })
            }
        })?;
        let reply = confirmed(receive, false).await?;
        if host.faulted() || host.closing.load(Ordering::SeqCst) || host.lock_state().epoch != epoch
        {
            return Err(Error::new(
                503,
                "Management authority changed; no new proof is returned.",
            ));
        }
        return Ok(reply);
    }
    if request.target == "/api/pause"
        && !fault
        && value::boolean(&input, value::prop(&input, "paused")) == Some(true)
    {
        host.command(json!({"op":"invalidateSelection"}))?;
        #[cfg(feature = "fixture")]
        host.hooks.wait_async("platform:pause").await;
    }
    let (receive, next, epoch, expansion, reply) = {
        let mut state = host.lock_state();
        if host.faulted() && !recovery {
            return Err(Error::new(503, "Ordinary work is frozen."));
        }
        let (next, reply, expansion) =
            mutation(&state.config, &request.target, &input, host.faulted())?;
        let epoch = state.epoch + u64::from(!expansion);
        let receive = host.persistence.config(next.try_clone()?)?;
        crate::operations::cancel_pending(&mut state);
        if !expansion {
            state.config = next.try_clone()?;
            state.epoch += 1;
            if value::boolean(&state.config, value::prop(&state.config, "paused")) == Some(true) {
                // Registration is state -> platform too: no picker can miss both
                // the early lifecycle invalidation and this installed restriction.
                host.platform.cancel_picker();
            }
            state.persistence_warning = Some("Restriction persistence is pending.".into());
        }
        (receive, next, epoch, expansion, reply)
    };
    if let Err(error) = confirmed(receive, recovery).await {
        let mut state = host.lock_state();
        if state.epoch == epoch {
            state.persistence_warning=Some("EPERSISTENCE: Restriction durability is not confirmed; ownership remains held while work is pending.".into());
        }
        return Err(error);
    }
    let mut state = host.lock_state();
    if expansion {
        if host.faulted() || state.epoch != epoch || host.closing.load(Ordering::SeqCst) {
            return Err(Error::new(
                503,
                "Permission changed while saving; expansion was not activated.",
            ));
        }
        state.config = next;
        state.epoch += 1;
    }
    if expansion || state.epoch == epoch {
        state.persistence_warning = None;
    }
    Ok(Reply::json(reply))
}
pub(crate) fn mutation(
    config: &Document,
    target: &str,
    input: &Document,
    fault: bool,
) -> Result<(Document, serde_json::Value, bool)> {
    let mut next = config.try_clone()?;
    // The independent latch is authoritative even before poison obtains the state lock.
    if fault {
        value::put(&mut next, "paused", Value::Bool(true))?;
    }
    let (reply, expansion) = if target == "/api/pause" {
        value::fields(input, &["paused"])?;
        let paused = value::boolean(input, value::prop(input, "paused"))
            .ok_or_else(|| Error::new(400, "An explicit boolean is required."))?;
        if fault && !paused {
            return Err(Error::new(
                503,
                "Unpause is unavailable after a lifecycle failure.",
            ));
        }
        value::put(&mut next, "paused", Value::Bool(paused))?;
        (json!({"paused":paused}), !paused)
    } else {
        value::fields(input, &["id"])?;
        let id = value::string(input, value::prop(input, "id"))
            .filter(|s| {
                s.len() == 36
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
            })
            .ok_or_else(|| Error::new(400, "Invalid identifier."))?;
        let account = target == "/api/account-root/remove";
        let key = if account { "accountRoots" } else { "roots" };
        let roots = value::array(&next, value::prop(&next, key)).unwrap_or_default();
        let len = roots.len();
        let remaining = roots
            .into_iter()
            .filter(|r| value::string(&next, value::get(&next, *r, "id")).as_deref() != Some(&id))
            .collect::<Vec<_>>();
        if account && remaining.len() == len {
            return Err(Error::new(404, "Account folder is not shared."));
        }
        value::put(&mut next, key, Value::Array(remaining))?;
        (
            if account {
                json!({"ok":true,"localAccessRevoked":true,"cloudMembershipRemoved":false})
            } else {
                json!({"ok":true})
            },
            false,
        )
    };
    let revision =
        value::number(&next, value::prop(&next, "accountPolicyRevision")).unwrap_or(0.0) + 1.0;
    value::put(&mut next, "accountPolicyRevision", Value::Number(revision))?;
    if let Some(selected) = value::prop(&next, "connectionGuide")
        .and_then(|g| value::string(&next, value::get(&next, g, "rootId")))
        && !value::array(&next, value::prop(&next, "roots"))
            .unwrap_or_default()
            .iter()
            .any(|r| {
                value::string(&next, value::get(&next, *r, "id")).as_deref() == Some(&selected)
            })
    {
        value::remove(&mut next, "connectionGuide")?;
    }
    Ok((next, reply, expansion))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restrictive_fault_snapshot_cannot_inherit_pre_overlay_unpaused_memory() {
        let before=value::parse(br#"{"paused":false,"roots":[{"id":"00000000-0000-0000-0000-000000000000","write":false}],"unknown":{"keep":true}}"#).unwrap();
        let input = value::parse(br#"{"id":"00000000-0000-0000-0000-000000000000"}"#).unwrap();
        let (next, _, _) = mutation(&before, "/api/root/remove", &input, true).unwrap();
        assert_eq!(
            value::boolean(&next, value::prop(&next, "paused")),
            Some(true)
        );
        assert!(
            value::array(&next, value::prop(&next, "roots"))
                .unwrap()
                .is_empty()
        );
        assert!(value::prop(&next, "unknown").is_some());
    }
}
