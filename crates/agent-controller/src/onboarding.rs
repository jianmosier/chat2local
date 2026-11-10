//! Native account/instance consent adapter. The ordinary Worker authenticates
//! every receipt; this module never substitutes a local issuer.
use crate::{
    Error, Reply, Request, Result,
    runtime::Host,
    workflow::{self, Guard, Save, Slot},
    workflow_value::{Doc, hex_id, id, permitted, scopes, shares},
};
use chat2local_agent_platform::FolderBrowse;
use serde_json::json;
use std::sync::Arc;
pub fn flow_key(flow: &str) -> String {
    format!("onboarding-flow-{flow}")
}
pub fn intent_key(flow: &str) -> String {
    format!("onboarding-intent-{flow}")
}
pub fn selections(local: &Doc) -> Result<Vec<Doc>> {
    if local.has("reusedRoots") {
        local.array("reusedRoots")
    } else if local.has("selections") {
        local.array("selections")
    } else {
        Ok(vec![local.need("selection")?])
    }
}
pub fn policy_doc(config: &Doc, local: &Doc) -> Result<String> {
    let mut d = Doc::object()?;
    d.put("deviceId", json!(local.req("deviceId")?))?;
    d.put("origin", json!(local.req("origin")?))?;
    d.set("paused", config.need("paused")?)?;
    d.set("roots", config.need("roots")?)?;
    d.set(
        "accountRoots",
        Doc::list(
            config
                .array("accountRoots")?
                .into_iter()
                .filter(|r| r.s("intentId") != local.s("flowId"))
                .collect(),
        )?,
    )?;
    if local.s("accessProfile").as_deref() == Some("project") {
        d.put("accessProfile", json!("project"))?;
        let selected = local.array("selections")?;
        d.set(
            "terminalGrants",
            Doc::list(
                config
                    .array("terminalGrants")?
                    .into_iter()
                    .filter(|g| !selected.iter().any(|r| r.s("id") == g.s("rootId")))
                    .collect(),
            )?,
        )?;
    }
    d.set(
        "selection",
        if local.has("reusedRoots") {
            local.need("reusedRoots")?
        } else if local.has("selections") {
            local.need("selections")?
        } else {
            local.need("selection")?
        },
    )?;
    d.digest()
}
pub fn current(host: &Host, local: &Doc, guard: &Guard) -> Result<()> {
    guard.current(host)?;
    let state = host.lock_state();
    let identity = crate::tools::identity(&state.secrets)?;
    if local.s("deviceId").as_deref() != Some(&identity.device)
        || local.s("origin").as_deref() != Some(&identity.origin)
        || local.n("revision") != Some(workflow::policy(&state))
    {
        return Err(workflow::stale());
    }
    Ok(())
}
pub async fn checked(
    host: &Arc<Host>,
    path: String,
    mode: &str,
    old: Option<&Doc>,
) -> Result<(Doc, Arc<FolderBrowse>)> {
    let directory = host.store.directory().to_owned();
    let held = Arc::new(
        tokio::task::spawn_blocking(move || {
            let h = FolderBrowse::open(Some(&path), &directory)
                .map_err(|e| Error::new(400, e.message))?;
            if !h
                .selectable_checked()
                .map_err(|e| Error::new(400, e.message))?
            {
                return Err(Error::new(
                    400,
                    "Do not share an entire drive, user profile or protected directory.",
                ));
            }
            Ok(h)
        })
        .await
        .map_err(|_| Error::new(503, "Directory verification failed."))??,
    );
    let (dev, ino) = held
        .directory
        .node_identity()
        .map_err(|e| Error::new(400, e.message))?;
    let path = held.directory.path.to_str().ok_or_else(workflow::stale)?;
    let mut selected = Doc::object()?;
    selected.put(
        "id",
        json!(old.and_then(|d| d.s("id")).unwrap_or(crate::uuid()?)),
    )?;
    selected.put("path", json!(path))?;
    selected.put(
        "label",
        json!(
            old.and_then(|d| d.s("label")).unwrap_or(
                held.directory
                    .path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("Folder")
                    .into()
            )
        ),
    )?;
    selected.permission(mode)?;
    selected.put("dev", json!(dev))?;
    selected.put("ino", json!(ino))?;
    Ok((selected, held))
}
pub async fn assert_current(
    host: &Arc<Host>,
    local: &Doc,
    intent: &Doc,
    guard: &Guard,
) -> Result<Vec<Arc<FolderBrowse>>> {
    current(host, local, guard)?;
    let config = Doc(host.lock_state().config.try_clone()?);
    if intent.s("intentId") != local.s("flowId")
        || intent.s("policyDigest") != local.s("policyDigest")
        || Some(policy_doc(&config, local)?) != local.s("policyDigest")
    {
        return Err(workflow::stale());
    }
    let mut held = Vec::new();
    for selection in selections(local)? {
        let (checked, h) = checked(
            host,
            selection.req("path")?,
            &selection.req("writeMode")?,
            Some(&selection),
        )
        .await?;
        for key in ["path", "dev", "ino"] {
            if checked.s(key) != selection.s(key) {
                return Err(Error::new(409, "目录位置已变化，没有沿用旧授权。"));
            }
        }
        held.push(h);
    }
    current(host, local, guard)?;
    Ok(held)
}
pub async fn persist_local(
    host: &Arc<Host>,
    guard: &Guard,
    local: Doc,
    held: Vec<Arc<FolderBrowse>>,
) -> Result<Doc> {
    let g = guard.for_flow(&local)?;
    workflow::commit(
        host,
        Box::new(move |host| {
            Box::pin(async move {
                g.current(&host)?;
                let key = flow_key(&local.req("flowId")?);
                workflow::save(&host, g, Save::Private(key), local.copy()?, held).await?;
                Ok(local)
            })
        }),
    )
    .await
}
pub async fn call(
    host: &Arc<Host>,
    guard: &Guard,
    action: &str,
    local: &Doc,
    input: Doc,
) -> Result<Doc> {
    let (_, identity) = guard.credential.as_ref().ok_or_else(workflow::stale)?;
    if local.s("origin").as_deref() != Some(&identity.origin)
        || local.s("deviceId").as_deref() != Some(&identity.device)
    {
        return Err(workflow::stale());
    }
    let profile = local.s("profile").unwrap_or("account".into());
    if !["account", "instance"].contains(&profile.as_str()) {
        return Err(workflow::stale());
    }
    let mut body = Doc::object()?;
    body.put("flowId", json!(local.req("flowId")?))?;
    body.put("deviceId", json!(identity.device))?;
    body.put(
        "secret",
        json!(local.req(if ["start", "enroll"].contains(&action) {
            "bootstrap"
        } else {
            "sessionSecret"
        })?),
    )?;
    body.set("input", input)?;
    if profile == "instance" && ["start", "enroll"].contains(&action) && local.has("invitation") {
        body.set("invitation", local.need("invitation")?)?;
    }
    workflow::request(
        host,
        &guard.for_flow(local)?,
        &identity.origin,
        &format!("/{profile}/native/{action}"),
        Some(body),
        action,
    )
    .await
}
pub fn validate_intent(intent: &Doc) -> Result<()> {
    for k in ["intentId", "accountId", "connectionId", "deviceId"] {
        id(intent, k, 32)?;
    }
    for k in [
        "snapshotDigest",
        "policyDigest",
        "deviceEpoch",
        "requestDigest",
    ] {
        id(intent, k, 64)?;
    }
    shares(&intent.need("roots")?)?;
    scopes(&intent.need("scopes")?)?;
    let client = intent.req("clientId")?;
    if client.is_empty()
        || client.encode_utf16().count() > 512
        || client.chars().any(|c| c <= ' ' || c == '\u{7f}')
    {
        return Err(Error::new(403, "Invalid client receipt."));
    }
    let resource = intent.req("resource")?;
    let u = url::Url::parse(&resource).map_err(|_| workflow::stale())?;
    if resource.encode_utf16().count() > 2048
        || u.path() != "/mcp"
        || u.query().is_some()
        || u.fragment().is_some()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.as_str() != resource
        || crate::network::origin(&u.origin().ascii_serialization()).is_err()
    {
        return Err(Error::new(403, "Invalid resource receipt."));
    }
    Ok(())
}
pub fn match_receipt(intent: &Doc, remote: &Doc) -> Result<()> {
    if remote.n("version") != Some(1.) {
        return Err(Error::new(403, "Consent receipt version differs."));
    }
    validate_intent(remote)?;
    for key in [
        "intentId",
        "accountId",
        "connectionId",
        "deviceId",
        "deviceEpoch",
        "snapshotDigest",
        "policyDigest",
        "requestDigest",
        "clientId",
        "resource",
    ] {
        if intent.s(key) != remote.s(key) {
            return Err(Error::new(
                403,
                "Consent receipt differs from the displayed account/client/device/folders.",
            ));
        }
    }
    if shares(&intent.need("roots")?)?.raw()? != shares(&remote.need("roots")?)?.raw()?
        || scopes(&intent.need("scopes")?)? != scopes(&remote.need("scopes")?)?
    {
        return Err(Error::new(403, "Consent receipt scope differs."));
    }
    Ok(())
}
pub async fn stage(host: &Arc<Host>, local: &Doc, guard: &Guard) -> Result<()> {
    let roots = shares(&Doc::list(
        selections(local)?
            .into_iter()
            .map(|r| Doc::json(json!({"rootId":r.req("id")?,"mode":r.req("writeMode")?})))
            .collect::<Result<_>>()?,
    )?)?;
    let mut input = Doc::object()?;
    input.set("roots", roots.copy()?)?;
    input.set("policyDigest", local.need("policyDigest")?)?;
    let intent = call(host, guard, "prepare", local, input).await?;
    validate_intent(&intent)?;
    let context = local.need("context")?;
    for key in [
        "accountId",
        "clientId",
        "requestDigest",
        "resource",
        "deviceEpoch",
    ] {
        if intent.s(key) != context.s(key) {
            return Err(Error::new(403, "待确认范围与请求应用不一致。"));
        }
    }
    if intent.s("intentId") != local.s("flowId")
        || intent.s("deviceId") != local.s("deviceId")
        || intent.s("policyDigest") != local.s("policyDigest")
        || context
            .s("connectionId")
            .is_some_and(|id| !id.is_empty() && intent.s("connectionId").as_deref() != Some(&id))
        || shares(&intent.need("roots")?)?.raw()? != roots.raw()?
        || scopes(&intent.need("scopes")?)? != scopes(&context.need("scopes")?)?
    {
        return Err(Error::new(403, "待确认范围与设备、目录或请求应用不一致。"));
    }
    let l = local.copy()?;
    let g = guard.for_flow(local)?;
    workflow::commit(
        host,
        Box::new(move |host| {
            Box::pin(async move {
                let key = intent_key(&l.req("flowId")?);
                if let Some(old) = workflow::load(&host, key.clone()).await? {
                    let old = old.need("intent")?;
                    if old.s("snapshotDigest") != intent.s("snapshotDigest")
                        || old.s("policyDigest") != intent.s("policyDigest")
                    {
                        return Err(workflow::stale());
                    }
                    return Doc::object();
                }
                let held = assert_current(&host, &l, &intent, &g).await?;
                let mut record = Doc::json(json!({"version":1}))?;
                record.set("intent", intent)?;
                record.put("phase", json!("awaiting-consent"))?;
                record.put("userConfirmed", json!(false))?;
                record.put("confirmations", json!(0))?;
                workflow::save(&host, g, Save::Private(key), record, held).await?;
                Doc::object()
            })
        }),
    )
    .await?;
    Ok(())
}
pub async fn view(host: &Arc<Host>, local: &Doc) -> Result<Doc> {
    let record = workflow::load(host, intent_key(&local.req("flowId")?)).await?;
    let context = local.get("context")?.unwrap_or(Doc::object()?);
    let mut d = Doc::object()?;
    if local.has("accessProfile") {
        d.set("accessProfile", local.need("accessProfile")?)?;
    }
    d.put(
        "terminalRequested",
        json!(
            local.s("accessProfile").as_deref() == Some("project")
                || context.get("scopes")?.is_some_and(
                    |v| scopes(&v).is_ok_and(|s| s.iter().any(|s| s == "terminal:execute"))
                )
        ),
    )?;
    d.set("flowId", local.need("flowId")?)?;
    for key in ["displayName", "clientName", "callbackOrigin"] {
        if let Some(v) = context.get(key)? {
            d.set(key, v)?;
        }
    }
    if let Some(v) = local.get("deviceName")? {
        d.set("deviceName", v)?;
    }
    d.put("reuseExisting", json!(local.has("reusedRoots")))?;
    let projected = |r: Doc| {
        Doc::json(json!({"label":r.req("label")?,"path":r.req("path")?,"mode":r.req("writeMode")?}))
    };
    if local.has("reusedRoots") || local.has("selections") {
        d.set(
            "selections",
            Doc::list(
                selections(local)?
                    .into_iter()
                    .map(projected)
                    .collect::<Result<_>>()?,
            )?,
        )?;
    }
    d.set(
        "selection",
        local
            .get("selection")?
            .map(projected)
            .transpose()?
            .unwrap_or(Doc::parse("null")?),
    )?;
    let connected = record
        .as_ref()
        .is_some_and(|r| r.s("phase").as_deref() == Some("connected"));
    if let Some(record) = record {
        d.set(
            "snapshotDigest",
            record.need("intent")?.need("snapshotDigest")?,
        )?;
        d.set("intentId", record.need("intent")?.need("intentId")?)?;
        d.set("phase", record.need("phase")?)?;
        d.put("requiresConsent", json!(!record.b("userConfirmed")))?;
        d.set("confirmationCount", record.need("confirmations")?)?;
        d.put("fileReadWriteVerified", json!(false))?;
        d.set("error", record.get("error")?.unwrap_or(Doc::parse("null")?))?;
    } else {
        d.put("snapshotDigest", json!(null))?;
        d.put("requiresConsent", json!(false))?;
        d.put("phase", json!("choose-folder"))?;
        d.put("confirmationCount", json!(0))?;
    }
    d.put("connected", json!(connected))?;
    d.put(
        "finishUrl",
        if connected {
            json!(format!(
                "{}/{}/finish?flow={}",
                local.req("origin")?,
                local.s("profile").unwrap_or("account".into()),
                local.req("flowId")?
            ))
        } else {
            json!(null)
        },
    )?;
    Ok(d)
}
pub async fn prepare_existing(host: &Arc<Host>, local: &mut Doc, guard: &Guard) -> Result<()> {
    let context = local.need("context")?;
    if local.s("profile").as_deref() != Some("instance")
        || !context.b("reuseExisting")
        || workflow::load(host, intent_key(&local.req("flowId")?))
            .await?
            .is_some()
    {
        return Ok(());
    }
    if !local.has("reusedRoots") {
        current(host, local, guard)?;
        let config = Doc(host.lock_state().config.try_clone()?);
        let allowed = match context.get("recoveryRoots")? {
            Some(v) if v.raw()? == "null" => None,
            Some(v) => Some(shares(&v)?.items()?),
            None => return Err(workflow::stale()),
        };
        let scopes = scopes(&context.need("scopes")?)?;
        let mut roots = config.array("roots")?;
        if allowed.is_some() {
            roots.extend(
                config
                    .array("accountRoots")?
                    .into_iter()
                    .filter(|r| r.s("connectionId") == context.s("connectionId")),
            );
        }
        let mut selected = Vec::new();
        let mut held = Vec::new();
        for root in roots {
            let remote = allowed
                .as_ref()
                .and_then(|a| a.iter().find(|r| r.s("rootId") == root.s("id")));
            if allowed.is_some() && remote.is_none() {
                continue;
            }
            let local_mode = root.mode()?;
            let remote_mode = remote
                .map(|r| r.req("mode"))
                .transpose()?
                .unwrap_or(local_mode.clone());
            let (mode, h) = checked(
                host,
                root.req("path")?,
                permitted(&local_mode, &remote_mode, &scopes),
                Some(&root),
            )
            .await?;
            selected.push(mode);
            held.push(h);
        }
        if selected.is_empty() {
            return Err(Error::new(
                409,
                "本机没有可沿用的已授权目录。不会自动添加其他目录。",
            ));
        }
        local.set("reusedRoots", Doc::list(selected)?)?;
        local.put("policyDigest", json!(policy_doc(&config, local)?))?;
        *local = persist_local(host, guard, local.copy()?, held).await?;
    }
    stage(host, local, guard).await
}
pub async fn reconcile(
    host: &Arc<Host>,
    local: &Doc,
    guard: &Guard,
    confirmation: Option<&Doc>,
) -> Result<()> {
    let key = intent_key(&local.req("flowId")?);
    let mut record = workflow::load(host, key.clone())
        .await?
        .ok_or_else(|| Error::new(409, "No resumable consent."))?;
    let intent = record.need("intent")?;
    if let Some(input) = confirmation
        && (input.s("snapshotDigest") != intent.s("snapshotDigest")
            || input.s("confirmation").as_deref() != Some("allow-shared-folders-v1"))
    {
        return Err(Error::new(
            400,
            "Use the displayed confirmation for this exact selection.",
        ));
    }
    assert_current(host, local, &intent, guard).await?;
    if !record.b("userConfirmed") {
        if confirmation.is_none() {
            return Ok(());
        }
        record.put("userConfirmed", json!(true))?;
        record.put("confirmations", json!(1))?;
        record.put("phase", json!("confirming"))?;
        save_record(host, local, guard, record.copy()?).await?;
    }
    let outcome = async {
        let mut remote = call(host, guard, "status", local, Doc::object()?).await?;
        match_receipt(&intent, &remote)?;
        if remote.s("phase").as_deref() == Some("prepared") {
            let saved = workflow::load(host, key.clone())
                .await?
                .ok_or_else(workflow::stale)?;
            if !saved.b("userConfirmed") {
                return Err(Error::new(403, "No saved user confirmation."));
            }
            assert_current(host, local, &intent, guard).await?;
            remote = call(
                host,
                guard,
                "confirm",
                local,
                Doc::json(json!({"snapshotDigest":intent.req("snapshotDigest")?}))?,
            )
            .await?;
            match_receipt(&intent, &remote)?;
        }
        if !matches!(remote.s("phase").as_deref(), Some("consented" | "active")) {
            return Err(Error::new(
                409,
                "Consent has not been authenticated by the service.",
            ));
        }
        activate(host, local, guard, &intent).await?;
        if remote.s("phase").as_deref() != Some("active") {
            remote = call(
                host,
                guard,
                "activate",
                local,
                Doc::json(json!({"snapshotDigest":intent.req("snapshotDigest")?}))?,
            )
            .await?;
            match_receipt(&intent, &remote)?;
        }
        if remote.s("phase").as_deref() != Some("active") {
            return Err(Error::new(409, "Connection activation not confirmed."));
        }
        Ok(())
    }
    .await;
    if let Err(e) = outcome {
        record.put("phase", json!("resume-required"))?;
        record.put("error",json!("Connection outcome is not confirmed. Resume this attempt; do not select folders or consent again."))?;
        let _ = save_record(host, local, guard, record).await;
        return Err(e);
    }
    record.put("phase", json!("connected"))?;
    record.put("error", json!(null))?;
    save_record(host, local, guard, record).await
}
async fn save_record(host: &Arc<Host>, local: &Doc, guard: &Guard, record: Doc) -> Result<()> {
    let g = guard.for_flow(local)?;
    let local = local.copy()?;
    workflow::commit(
        host,
        Box::new(move |host| {
            Box::pin(async move {
                let held = assert_current(&host, &local, &record.need("intent")?, &g).await?;
                workflow::save(
                    &host,
                    g,
                    Save::Private(intent_key(&local.req("flowId")?)),
                    record,
                    held,
                )
                .await?;
                Doc::object()
            })
        }),
    )
    .await?;
    Ok(())
}
async fn activate(host: &Arc<Host>, local: &Doc, guard: &Guard, intent: &Doc) -> Result<()> {
    let g = guard.for_flow(local)?;
    let local = local.copy()?;
    let intent = intent.copy()?;
    workflow::commit(
        host,
        Box::new(move |host| {
            Box::pin(async move {
                let held = assert_current(&host, &local, &intent, &g).await?;
                let saved = workflow::load(&host, intent_key(&local.req("flowId")?))
                    .await?
                    .ok_or_else(workflow::stale)?;
                if !saved.b("userConfirmed")
                    || saved.need("intent")?.s("snapshotDigest") != intent.s("snapshotDigest")
                {
                    return Err(Error::new(403, "本机确认未持久化，没有激活目录。"));
                }
                if local.has("reusedRoots") {
                    return Doc::object();
                }
                let mut config = Doc(host.lock_state().config.try_clone()?);
                let mut roots = config.array("accountRoots")?;
                let mut grants = config.array("terminalGrants")?;
                let prior_roots = roots.len();
                let prior_grants = grants.len();
                for selected in selections(&local)? {
                    let mut root = Doc::object()?;
                    for key in ["id", "path", "label"] {
                        root.set(key, selected.need(key)?)?;
                    }
                    root.permission(&selected.req("writeMode")?)?;
                    for key in ["accountId", "connectionId"] {
                        root.set(key, intent.need(key)?)?;
                    }
                    root.put("intentId", json!(local.req("flowId")?))?;
                    if let Some(old) = roots.iter().find(|r| r.s("id") == root.s("id")) {
                        if old.raw()? != root.raw()? {
                            return Err(workflow::stale());
                        }
                    } else {
                        roots.push(root.copy()?);
                    }
                    if local.s("accessProfile").as_deref() == Some("project") {
                        if root.s("writeMode").as_deref() != Some("direct") {
                            return Err(workflow::stale());
                        }
                        let mut grant = Doc::object()?;
                        grant.put("connectionId", json!(intent.req("connectionId")?))?;
                        grant.put("rootId", json!(root.req("id")?))?;
                        grant.put("resource", json!(intent.req("resource")?))?;
                        grant.put("enabled", json!(true))?;
                        if let Some(old) = grants.iter().find(|r| {
                            r.s("connectionId") == grant.s("connectionId")
                                && r.s("rootId") == grant.s("rootId")
                        }) {
                            if old.raw()? != grant.raw()? {
                                return Err(workflow::stale());
                            }
                        } else {
                            grants.push(grant);
                        }
                    }
                }
                if roots.len() > 100 {
                    return Err(Error::new(429, "已达到共享目录数量限制。"));
                }
                if roots.len() != prior_roots || grants.len() != prior_grants {
                    config.set("accountRoots", Doc::list(roots)?)?;
                    if local.s("accessProfile").as_deref() == Some("project") {
                        config.set("terminalGrants", Doc::list(grants)?)?;
                    }
                    #[cfg(feature = "fixture")]
                    host.hooks.wait_async("workflow:activate").await;
                    workflow::save(&host, g, Save::Config, config, held).await?;
                }
                Doc::object()
            })
        }),
    )
    .await?;
    Ok(())
}
pub async fn handle(host: &Arc<Host>, request: Request, input: Option<Doc>) -> Result<Reply> {
    let profile = if request.target.starts_with("/instance-connect") {
        "instance"
    } else {
        "account"
    };
    let base = format!("/{profile}-connect");
    if request.target == base && request.method == "GET" {
        if !request.header("sec-fetch-dest").is_empty()
            && request.header("sec-fetch-dest") != "document"
        {
            return Err(Error::new(403, "Open this page as a document."));
        }
        let nonce = host.workflows.page(profile, request.header("cookie"))?;
        let mut body =
            include_str!("../../../src/agent/ui/account-connect.html").replace("{{NONCE}}", &nonce);
        if profile == "instance" {
            body = body
                .replace("/account-connect.js", "/instance-connect.js")
                .replace("账号", "私人实例");
        }
        return Ok(Reply {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body,
            cookie: Some(format!(
                "c2l_{profile}_local={nonce}; HttpOnly; SameSite=Strict; Path={base}; Max-Age=86400"
            )),
        });
    }
    let action = request
        .target
        .strip_prefix(&(base + "/"))
        .filter(|a| ["start", "choose", "status", "confirm", "resume"].contains(a))
        .ok_or_else(|| Error::new(404, "Unknown onboarding action."))?
        .to_owned();
    let input = input.ok_or_else(workflow::stale)?;
    input.fields(if action == "start" {
        &["nonce", "origin", "flow"]
    } else if action == "confirm" {
        &["nonce", "flowId", "snapshotDigest", "confirmation"]
    } else {
        &["nonce", "flowId"]
    })?;
    let flow = if action == "start" {
        let raw = input.req("flow")?;
        let (a, b) = raw.split_once('.').ok_or_else(workflow::stale)?;
        if !hex_id(a, 32) || !hex_id(b, 64) {
            return Err(Error::new(403, "Invalid onboarding link."));
        }
        a.to_owned()
    } else {
        id(&input, "flowId", 32)?
    };
    let nonce = host.workflows.session(
        profile,
        &input,
        request.header("cookie"),
        if action == "start" { None } else { Some(&flow) },
    )?;
    let guard = Guard::capture(host, request.disconnected, false)?;
    let owner = host.clone();
    let profile = profile.to_owned();
    let fingerprint = if ["start", "choose"].contains(&action.as_str()) {
        input.digest()?
    } else if action == "confirm" {
        input.req("snapshotDigest")?
    } else {
        String::new()
    };
    let key = if ["confirm", "resume"].contains(&action.as_str()) {
        format!("consent:{flow}")
    } else {
        format!("{action}:{flow}")
    };
    let result = host
        .workflows
        .coalesce(host, key, fingerprint, 16, async move {
            perform(&owner, &profile, &action, input, flow, nonce, guard).await
        })
        .await?;
    workflow::reply(result)
}
async fn perform(
    host: &Arc<Host>,
    profile: &str,
    action: &str,
    input: Doc,
    flow: String,
    nonce: String,
    mut guard: Guard,
) -> Result<Doc> {
    let mut local;
    if action == "start" {
        let origin = crate::network::origin(&input.req("origin")?)?;
        let raw = input.req("flow")?;
        let bootstrap = raw
            .split_once('.')
            .ok_or_else(workflow::stale)?
            .1
            .to_owned();
        let trusted = crate::setup::origin(host, profile)?;
        if trusted.as_deref() != Some(&origin) {
            return Err(Error::new(403, "接入链接与本机服务不匹配。"));
        }
        let g = guard.clone();
        let selected = origin.clone();
        let identity=workflow::commit(host,Box::new(move|host|Box::pin(async move{g.current(&host)?;let mut secrets=Doc(host.lock_state().secrets.try_clone()?);if let Some(id)=secrets.get("identity")?{return Ok(id);}
if let Some(p)=secrets.get("accountEnrollmentPending")?{if p.s("origin").as_deref()!=Some(&selected){return Err(workflow::stale());}return Ok(p);}let identity=Doc::json(json!({"origin":selected,"deviceId":crate::random(16)?,"deviceKey":crate::random(32)?}))?;secrets.set("accountEnrollmentPending",identity.copy()?)?;workflow::save(&host,g,Save::Secrets,secrets,vec![]).await?;Ok(identity)}))).await?;
        let slot = if crate::tools::identity(&host.lock_state().secrets).is_ok() {
            Slot::Active
        } else {
            Slot::AccountEnrollmentPending
        };
        guard.credential = Some((
            slot,
            workflow::identity_at(&host.lock_state().secrets, slot)?,
        ));
        local = if let Some(saved) = workflow::load(host, flow_key(&flow)).await? {
            if saved.s("profile").unwrap_or("account".into()) != profile
                || saved.s("origin").as_deref() != Some(&origin)
                || saved.s("deviceId") != identity.s("deviceId")
                || saved.s("bootstrap").as_deref() != Some(&bootstrap)
                || saved
                    .n("until")
                    .is_none_or(|t| t < crate::management::now())
            {
                return Err(workflow::stale());
            }
            saved
        } else {
            let mut l = Doc::object()?;
            l.put("flowId", json!(flow))?;
            l.put("bootstrap", json!(bootstrap))?;
            l.put("origin", json!(origin))?;
            l.put("profile", json!(profile))?;
            if profile == "instance" {
                let secrets = Doc(host.lock_state().secrets.try_clone()?);
                if let Some(invitation) = secrets
                    .get("privateInstanceInvitation")?
                    .and_then(|v| v.s("invitation"))
                {
                    l.put("invitation", json!(invitation))?;
                }
            }
            l.set("deviceId", identity.need("deviceId")?)?;
            l.put(
                "deviceName",
                json!(chat2local_agent_platform::computer_name().unwrap_or("这台电脑".into())),
            )?;
            l.put("sessionSecret", json!(crate::random(32)?))?;
            l.put("revision", json!(guard.policy))?;
            l.put("until", json!(crate::management::now() + 86400000.))?;
            persist_local(host, &guard, l, vec![]).await?
        };
        if slot != Slot::Active {
            let receipt = call(
                host,
                &guard,
                "enroll",
                &local,
                Doc::json(json!({"sessionSecret":local.req("sessionSecret")?}))?,
            )
            .await?;
            if !receipt.b("enrolled") || receipt.s("deviceId") != local.s("deviceId") {
                return Err(workflow::stale());
            }
            let g = guard.clone();
            let accepted = identity.copy()?;
            workflow::commit(
                host,
                Box::new(move |host| {
                    Box::pin(async move {
                        let mut secrets = Doc(host.lock_state().secrets.try_clone()?);
                        g.current(&host)?;
                        secrets.set("identity", accepted)?;
                        secrets.del("accountEnrollmentPending")?;
                        workflow::save(&host, g, Save::Secrets, secrets, vec![]).await?;
                        Doc::object()
                    })
                }),
            )
            .await?;
            guard.credential = Some((
                Slot::Active,
                crate::tools::identity(&host.lock_state().secrets)?,
            ));
            let g = guard.clone();
            let relay = origin.clone();
            workflow::commit(
                host,
                Box::new(move |host| {
                    Box::pin(async move {
                        g.current(&host)?;
                        let mut config = Doc(host.lock_state().config.try_clone()?);
                        config.put("relay", json!(relay))?;
                        workflow::save(&host, g, Save::Config, config, vec![]).await?;
                        Doc::object()
                    })
                }),
            )
            .await?;
            host.command(json!({"op":"bridgeStart","hasIdentity":true,"now":crate::management::now() as u64}))?;
        }
        current(host, &local, &guard)?;
        if !local.has("context") {
            let mut body = Doc::json(json!({"sessionSecret":local.req("sessionSecret")?}))?;
            let retained = {
                let s = host.lock_state();
                let c = Doc(s.config.try_clone()?);
                !c.array("roots")?.is_empty() || !c.array("accountRoots")?.is_empty()
            };
            if profile == "instance" && retained {
                body.put("reuseExisting", json!(true))?;
            }
            let context = call(host, &guard, "start", &local, body).await?;
            if context.s("flowId").as_deref() != Some(&flow)
                || context.s("deviceId") != local.s("deviceId")
                || context.s("resource") != Some(format!("{origin}/mcp"))
            {
                return Err(Error::new(403, "Service context differs."));
            }
            id(&context, "accountId", 32)?;
            id(&context, "deviceEpoch", 64)?;
            scopes(&context.need("scopes")?)?;
            local.set("context", context)?;
            local = persist_local(host, &guard, local, vec![]).await?;
        }
        prepare_existing(host, &mut local, &guard).await?;
        host.workflows.bind(&nonce, &flow)?;
        return view(host, &local).await;
    }
    local = workflow::load(host, flow_key(&flow))
        .await?
        .ok_or_else(workflow::stale)?;
    if local.s("profile").unwrap_or("account".into()) != profile
        || local
            .n("until")
            .is_none_or(|t| t < crate::management::now())
    {
        return Err(workflow::stale());
    }
    guard.credential = Some((
        Slot::Active,
        crate::tools::identity(&host.lock_state().secrets)?,
    ));
    current(host, &local, &guard)?;
    if action == "status" {
        return view(host, &local).await;
    }
    if action == "choose" {
        if workflow::load(host, intent_key(&flow)).await?.is_some() {
            return view(host, &local).await;
        }
        if !local.has("selection") {
            let revision = host.platform.selection_revision();
            guard.selection = Some(revision);
            let chosen = host.platform.pick(host, guard.disconnected.clone()).await?;
            let chosen = Doc::parse(&chosen.body)?;
            let Some(path) = chosen.s("path") else {
                return view(host, &local).await;
            };
            current(host, &local, &guard)?;
            if revision != host.platform.selection_revision() {
                return Err(workflow::stale());
            }
            let mode = if scopes(&local.need("context")?.need("scopes")?)?
                .iter()
                .any(|s| s == "files:write")
            {
                "direct"
            } else {
                "read-only"
            };
            let (selection, held) = checked(host, path, mode, None).await?;
            local.set("selection", selection)?;
            let config = Doc(host.lock_state().config.try_clone()?);
            local.put("policyDigest", json!(policy_doc(&config, &local)?))?;
            local = persist_local(host, &guard, local, vec![held]).await?;
        }
        stage(host, &local, &guard).await?;
    } else {
        reconcile(
            host,
            &local,
            &guard,
            if action == "confirm" {
                Some(&input)
            } else {
                None
            },
        )
        .await?;
    }
    view(host, &local).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_receipt_authority_field_is_compared_by_production_validator() {
        let original = json!({"version":1,"intentId":"a".repeat(32),"accountId":"b".repeat(32),"connectionId":"c".repeat(32),"deviceId":"d".repeat(32),"deviceEpoch":"a".repeat(64),"snapshotDigest":"b".repeat(64),"policyDigest":"c".repeat(64),"requestDigest":"d".repeat(64),"clientId":"native-client","resource":"https://relay.example.test/mcp","roots":[{"rootId":"folder","mode":"direct"}],"scopes":["files:read","files:write"]});
        let intent = Doc::json(original.clone()).unwrap();
        assert!(match_receipt(&intent, &intent).is_ok());
        for (key, value) in [
            ("version", json!(2)),
            ("intentId", json!("e".repeat(32))),
            ("accountId", json!("e".repeat(32))),
            ("connectionId", json!("e".repeat(32))),
            ("deviceId", json!("e".repeat(32))),
            ("deviceEpoch", json!("e".repeat(64))),
            ("snapshotDigest", json!("e".repeat(64))),
            ("policyDigest", json!("e".repeat(64))),
            ("requestDigest", json!("e".repeat(64))),
            ("clientId", json!("other-client")),
            ("resource", json!("https://other.example.test/mcp")),
            ("roots", json!([{"rootId":"folder","mode":"read-only"}])),
            ("roots", json!([{"rootId":"other","mode":"direct"}])),
            ("scopes", json!(["files:read"])),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            assert!(
                match_receipt(&intent, &Doc::json(changed).unwrap()).is_err(),
                "{key}"
            );
        }
    }
}
