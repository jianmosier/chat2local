//! Authenticated connection management. Remote records alone never create local grants.
use crate::{
    Error, Reply, Request, Result, onboarding as consent,
    runtime::Host,
    workflow::{self, Guard, Save, Slot},
    workflow_value::{Doc, hex_id, id, scopes},
};
use serde_json::json;
use std::sync::Arc;
pub async fn call(host: &Arc<Host>, guard: &Guard, action: &str, input: Doc) -> Result<Doc> {
    let (_, identity) = guard.credential.as_ref().ok_or_else(workflow::stale)?;
    let mut body = Doc::object()?;
    body.put("deviceId", json!(identity.device))?;
    body.set("input", input)?;
    workflow::request(
        host,
        guard,
        &identity.origin,
        &format!("/instance/manage/{action}"),
        Some(body),
        action,
    )
    .await
}
fn contains(parent: &str, child: &str) -> bool {
    let p = parent
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase();
    let c = child
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase();
    !p.is_empty() && (p == c || c.starts_with(&(p + "\\")))
}
fn rank(mode: Option<String>) -> i32 {
    match mode.as_deref() {
        Some("read-only") => 0,
        Some("review") => 1,
        Some("direct") => 2,
        _ => -1,
    }
}
fn covers(a: &Doc, b: &Doc) -> bool {
    a.b("locallyPresent")
        && b.b("locallyPresent")
        && rank(a.s("mode")) >= 0
        && rank(a.s("mode")) >= rank(b.s("mode"))
        && a.s("path")
            .zip(b.s("path"))
            .is_some_and(|(a, b)| contains(&a, &b))
        && (!b.b("terminalLocalEnabled") || a.b("terminalLocalEnabled"))
}
fn terminal(
    config: &Doc,
    connection: &str,
    resource: &str,
    root: &mut Doc,
    scopes: &[String],
) -> Result<()> {
    let local = config.array("terminalGrants")?.iter().any(|g| {
        g.b("enabled")
            && g.s("connectionId").as_deref() == Some(connection)
            && g.s("resource").as_deref() == Some(resource)
            && g.s("rootId") == root.s("rootId")
    });
    let scope = scopes.iter().any(|s| s == "terminal:execute");
    let available = root.b("locallyPresent") && root.s("mode").as_deref() == Some("direct");
    root.put("terminalLocalEnabled", json!(local))?;
    root.put("terminalScopeGranted", json!(scope))?;
    root.put("terminalAllowed", json!(available && local && scope))?;
    root.put(
        "terminalStatus",
        json!(if !available {
            "unavailable"
        } else if !local {
            "disabled"
        } else if !scope {
            "authorization-required"
        } else {
            "allowed"
        }),
    )?;
    root.put("terminalSandboxed", json!(false))
}
pub async fn connections(host: &Arc<Host>, guard: &Guard) -> Result<Doc> {
    let remote = call(host, guard, "connections", Doc::object()?).await?;
    let all = remote.need("connections")?.items()?;
    if all.len() > 20 {
        return Err(Error::new(409, "连接列表不匹配。"));
    }
    guard.current(host)?;
    let config = Doc(host.lock_state().config.try_clone()?);
    let identity = crate::tools::identity(&host.lock_state().secrets)?;
    let mut result = Vec::new();
    for mut c in all {
        let Some(connection) = c.s("connectionId").filter(|s| hex_id(s, 32)) else {
            continue;
        };
        let Ok(remote_roots) = c.need("roots").and_then(|v| v.items()) else {
            continue;
        };
        let mut candidates = config.array("roots")?;
        candidates.extend(
            config
                .array("accountRoots")?
                .into_iter()
                .filter(|r| r.s("connectionId").as_deref() == Some(&connection)),
        );
        let trusted = remote_roots
            .iter()
            .any(|r| candidates.iter().any(|l| l.s("id") == r.s("rootId")))
            || config.array("managedConnections")?.iter().any(|m| {
                m.s("connectionId").as_deref() == Some(&connection)
                    && m.s("deviceId").as_deref() == Some(&identity.device)
                    && m.s("origin").as_deref() == Some(&identity.origin)
            });
        if !trusted {
            continue;
        }
        let mut local = config.array("roots")?;
        local.extend(config.array("accountRoots")?);
        let scopes = scopes(&c.need("scopes")?)?;
        let mut roots = Vec::new();
        for mut r in remote_roots {
            let found = local.iter().find(|l| l.s("id") == r.s("rootId"));
            for key in ["path", "label"] {
                r.set(
                    key,
                    found
                        .map(|l| l.need(key))
                        .transpose()?
                        .unwrap_or(Doc::parse("null")?),
                )?;
            }
            r.put("locallyPresent", json!(found.is_some()))?;
            terminal(
                &config,
                &connection,
                &format!("{}/mcp", identity.origin),
                &mut r,
                &scopes,
            )?;
            roots.push(r);
        }
        let cover = (0..roots.len())
            .map(|i| {
                let mut candidates = (0..roots.len())
                    .filter(|j| {
                        *j != i
                            && covers(&roots[*j], &roots[i])
                            && (!covers(&roots[i], &roots[*j]) || *j < i)
                    })
                    .collect::<Vec<_>>();
                candidates.sort_by_key(|j| {
                    (
                        roots[*j]
                            .s("path")
                            .unwrap_or_default()
                            .split(['\\', '/'])
                            .filter(|p| !p.is_empty())
                            .count(),
                        *j,
                    )
                });
                candidates.first().and_then(|j| roots[*j].s("rootId"))
            })
            .collect::<Vec<_>>();
        for (r, cover) in roots.iter_mut().zip(cover) {
            r.put("coveredBy", json!(cover))?;
        }
        c.set("roots", Doc::list(roots)?)?;
        result.push(c);
    }
    let mut out = Doc::object()?;
    out.set("connections", Doc::list(result)?)?;
    Ok(out)
}
async fn load(host: &Arc<Host>, guard: &Guard, request: &str) -> Result<Doc> {
    let local = workflow::load(host, consent::flow_key(request))
        .await?
        .ok_or_else(workflow::stale)?;
    if !local.b("management")
        || local.s("profile").as_deref() != Some("instance")
        || local
            .n("until")
            .is_none_or(|t| t <= crate::management::now())
    {
        return Err(workflow::stale());
    }
    consent::current(host, &local, guard)?;
    Ok(local)
}
async fn view(host: &Arc<Host>, local: &Doc) -> Result<Doc> {
    let mut d = consent::view(host, local).await?;
    d.put("finishUrl", json!(null))?;
    d.put("management", json!(true))?;
    d.put(
        "connectionId",
        json!(local.get("context")?.and_then(|c| c.s("connectionId"))),
    )?;
    d.put("selection", json!(null))?;
    d.put("unchangedFoldersRetained", json!(true))?;
    Ok(d)
}
async fn manage(host: &Arc<Host>, guard: &Guard, action: &str, input: Doc) -> Result<Doc> {
    let request = id(&input, "requestId", 32)?;
    if action != "prepare" {
        let local = load(host, guard, &request).await?;
        if action != "status" {
            let confirmed = if action == "confirm" {
                let expected = if local.s("accessProfile").as_deref() == Some("project") {
                    "allow-project-files-and-terminal-v1"
                } else {
                    "allow-shared-folders-v1"
                };
                if input.s("confirmation").as_deref() != Some(expected) {
                    return Err(Error::new(403, "请确认本次显示的共享权限。"));
                }
                Some(Doc::json(
                    json!({"snapshotDigest":input.req("snapshotDigest")?,"confirmation":"allow-shared-folders-v1"}),
                )?)
            } else {
                None
            };
            consent::reconcile(host, &local, guard, confirmed.as_ref()).await?;
        }
        return view(host, &local).await;
    }
    let connection = id(&input, "connectionId", 32)?;
    let folders = input.need("folders")?.items()?;
    if folders.is_empty()
        || folders.len() > 20
        || input.has("accessProfile") && input.s("accessProfile").as_deref() != Some("project")
    {
        return Err(Error::new(400, "请选择 1–20 个具体文件夹。"));
    }
    let project = input.s("accessProfile").as_deref() == Some("project");
    for folder in &folders {
        folder.fields(&["path", "mode"])?;
        if folder.req("path")?.encode_utf16().count() > 4096
            || !matches!(
                folder.s("mode").as_deref(),
                Some("read-only" | "review" | "direct")
            )
            || project && folder.s("mode").as_deref() != Some("direct")
        {
            return Err(Error::new(400, "Invalid shared folder selection."));
        }
    }
    let digest = input.digest()?;
    let mut local = if let Some(old) = workflow::load(host, consent::flow_key(&request)).await? {
        if !old.b("management") || old.s("managementRequestDigest").as_deref() != Some(&digest) {
            return Err(workflow::stale());
        }
        consent::current(host, &old, guard)?;
        old
    } else {
        let selected = connections(host, guard)
            .await?
            .array("connections")?
            .into_iter()
            .find(|c| c.s("connectionId").as_deref() == Some(&connection))
            .ok_or_else(|| Error::new(403, "请选择这台电脑已经使用的连接。"))?;
        let ceiling = scopes(&selected.need("scopes")?)?;
        let identity = crate::tools::identity(&host.lock_state().secrets)?;
        let config = Doc(host.lock_state().config.try_clone()?);
        let mut selections = Vec::new();
        let mut held = Vec::new();
        for folder in folders {
            let mode = folder.req("mode")?;
            if mode == "direct" && !ceiling.iter().any(|s| s == "files:write")
                || mode == "review" && !ceiling.iter().any(|s| s == "files:propose")
            {
                return Err(Error::new(403, "原连接没有请求的操作权限。"));
            }
            let (r, h) = consent::checked(host, folder.req("path")?, &mode, None).await?;
            if selections.iter().any(|p: &Doc| p.s("path") == r.s("path")) {
                continue;
            }
            if selected
                .array("roots")?
                .iter()
                .any(|old| old.b("locallyPresent") && old.s("path") == r.s("path"))
            {
                return Err(Error::new(409, "此文件夹已共享，原权限保持不变。"));
            }
            selections.push(r);
            held.push(h);
        }
        let mut local = Doc::object()?;
        local.put("profile", json!("instance"))?;
        local.put("management", json!(true))?;
        if project {
            local.put("accessProfile", json!("project"))?;
        }
        local.put("managementRequestDigest", json!(digest))?;
        local.put("flowId", json!(request))?;
        local.put("origin", json!(identity.origin))?;
        local.put("deviceId", json!(identity.device))?;
        local.put(
            "deviceName",
            json!(chat2local_agent_platform::computer_name().unwrap_or("这台电脑".into())),
        )?;
        local.put("sessionSecret", json!(crate::random(32)?))?;
        local.put("revision", json!(guard.policy))?;
        local.put("until", json!(crate::management::now() + 86400000.))?;
        local.set("selections", Doc::list(selections)?)?;
        local.put("policyDigest", json!(consent::policy_doc(&config, &local)?))?;
        consent::persist_local(host, guard, local, held).await?
    };
    if !local.has("context") {
        let context=call(host,guard,"start",Doc::json(json!({"flowId":request,"connectionId":connection,"sessionSecret":local.req("sessionSecret")?}))?).await?;
        if !context.b("management")
            || context.s("flowId") != local.s("flowId")
            || context.s("deviceId") != local.s("deviceId")
            || context.s("resource") != Some(format!("{}/mcp", local.req("origin")?))
            || context.s("connectionId").as_deref() != Some(&connection)
        {
            return Err(Error::new(403, "目录管理响应不匹配。"));
        }
        local.set("context", context)?;
        local = consent::persist_local(host, guard, local, vec![]).await?;
    }
    if workflow::load(host, consent::intent_key(&request))
        .await?
        .is_none()
    {
        consent::stage(host, &local, guard).await?;
    }
    view(host, &local).await
}
fn removal_policy(host: &Host) -> Result<String> {
    let s = host.lock_state();
    let c = Doc(s.config.try_clone()?);
    Doc::list(vec![
        Doc::json(json!(
            crate::tools::identity(&s.secrets).ok().map(|i| i.device)
        ))?,
        c.need("roots")?,
        Doc::list(c.array("accountRoots")?)?,
        Doc::list(c.array("terminalGrants")?)?,
        Doc::json(json!(workflow::policy(&s)))?,
    ])?
    .digest()
}
fn root_summary(root: &Doc) -> Result<Doc> {
    let mut d = Doc::object()?;
    for key in ["rootId", "path", "label", "mode"] {
        d.set(key, root.need(key)?)?;
    }
    Ok(d)
}
async fn preview(host: &Arc<Host>, guard: &Guard, input: &Doc) -> Result<Doc> {
    input.fields(&["connectionId", "rootId"])?;
    let connection = id(input, "connectionId", 32)?;
    let root = input.req("rootId")?;
    if root.len() != 36
        || !root
            .bytes()
            .all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::new(400, "请选择一个共享文件夹。"));
    }
    let before = removal_policy(host)?;
    let all = connections(host, guard).await?.array("connections")?;
    let connection = all
        .iter()
        .find(|c| c.s("connectionId").as_deref() == Some(&connection))
        .ok_or_else(workflow::stale)?;
    let roots = connection.array("roots")?;
    let target = roots
        .iter()
        .find(|r| {
            r.b("locallyPresent")
                && r.s("rootId").as_deref() == Some(&root)
                && r.s("path").is_some()
        })
        .ok_or_else(workflow::stale)?;
    let revision = connection
        .n("revision")
        .filter(|n| n.is_finite() && n.fract() == 0. && n.abs() <= 9007199254740991.)
        .ok_or_else(workflow::stale)?;
    let affected = roots
        .iter()
        .filter(|r| {
            r.b("locallyPresent")
                && r.s("path")
                    .is_some_and(|p| contains(&p, &target.s("path").unwrap()))
        })
        .collect::<Vec<_>>();
    let children = roots
        .iter()
        .filter(|r| {
            r.b("locallyPresent")
                && !affected.iter().any(|a| a.s("rootId") == r.s("rootId"))
                && r.s("path")
                    .is_some_and(|p| contains(&target.s("path").unwrap(), &p))
        })
        .map(root_summary)
        .collect::<Result<Vec<_>>>()?;
    let config = Doc(host.lock_state().config.try_clone()?);
    for r in &affected {
        if config
            .array("roots")?
            .iter()
            .any(|l| l.s("id") == r.s("rootId"))
            && all.iter().any(|c| {
                c.s("connectionId") != connection.s("connectionId")
                    && c.array("roots")
                        .is_ok_and(|rs| rs.iter().any(|a| a.s("rootId") == r.s("rootId")))
            })
        {
            return Err(Error::new(409, "该目录也用于其他连接，未更改权限。"));
        }
    }
    if before != removal_policy(host)? {
        return Err(workflow::stale());
    }
    let identity = crate::tools::identity(&host.lock_state().secrets)?;
    let mut p = Doc::object()?;
    p.put("requestId", json!(crate::random(16)?))?;
    p.set("connectionId", connection.need("connectionId")?)?;
    p.put("expectedRevision", json!(revision))?;
    p.put("deviceId", json!(identity.device))?;
    p.put("origin", json!(identity.origin))?;
    p.set("target", target.need("path")?)?;
    p.set(
        "folders",
        Doc::list(
            affected
                .iter()
                .map(|r| root_summary(r))
                .collect::<Result<_>>()?,
        )?,
    )?;
    p.put("policy", json!(before))?;
    p.put("until", json!(crate::management::now() + 300000.))?;
    p.put("snapshotDigest", json!(p.digest()?))?;
    let mut out = Doc::object()?;
    for key in ["requestId", "snapshotDigest", "target", "folders"] {
        out.set(key, p.need(key)?)?;
    }
    out.put("includesOverlaps", json!(affected.len() > 1))?;
    out.set("retainedChildren", Doc::list(children)?)?;
    out.put("filesDeleted", json!(false))?;
    let mut state = host.workflows.inner.lock().unwrap();
    state
        .previews
        .retain(|_, p| p.n("until").is_some_and(|t| t >= crate::management::now()));
    if state.previews.len() >= 16 {
        return Err(Error::new(429, "待确认操作过多。"));
    }
    state.previews.insert(p.req("requestId")?, p);
    Ok(out)
}
pub async fn change_policy(host: &Arc<Host>, guard: Guard, mut config: Doc) -> Result<()> {
    config.put("accountPolicyRevision", json!(guard.policy + 1.))?;
    if let Some(guide) = config.get("connectionGuide")? {
        let before = Doc(host.lock_state().config.try_clone()?);
        let old = before
            .array("roots")?
            .into_iter()
            .find(|r| r.s("id") == guide.s("rootId"));
        let new = config
            .array("roots")?
            .into_iter()
            .find(|r| r.s("id") == guide.s("rootId"));
        if old
            .as_ref()
            .zip(new.as_ref())
            .is_none_or(|(a, b)| a.mode().ok() != b.mode().ok())
        {
            config.del("connectionGuide")?;
        }
    }
    workflow::save(host, guard, Save::Config, config, vec![]).await?;
    crate::operations::cancel_pending(&mut host.lock_state());
    Ok(())
}
async fn synchronize(host: &Arc<Host>, guard: &Guard, request: String) -> Result<Doc> {
    let config = Doc(host.lock_state().config.try_clone()?);
    let Some(saved) = config
        .array("shareRemovals")?
        .into_iter()
        .find(|r| r.s("requestId").as_deref() == Some(&request))
    else {
        return Doc::json(
            json!({"requestId":request,"localRevoked":true,"cloudSynced":true,"filesDeleted":false}),
        );
    };
    let work = async {
        let identity = crate::tools::identity(&host.lock_state().secrets)?;
        if saved.s("origin").as_deref() != Some(&identity.origin)
            || saved.s("deviceId").as_deref() != Some(&identity.device)
        {
            return Err(workflow::stale());
        }
        let mut input = Doc::object()?;
        for key in ["requestId", "connectionId", "rootIds", "expectedRevision"] {
            input.set(key, saved.need(key)?)?;
        }
        let result = call(host, guard, "remove", input).await?;
        if !result.b("removed")
            || result.s("connectionId") != saved.s("connectionId")
            || result.need("rootIds")?.raw()? != saved.need("rootIds")?.raw()?
        {
            return Err(Error::new(409, "撤销结果不匹配。"));
        }
        let g = guard.clone();
        let request = request.clone();
        workflow::commit(
            host,
            Box::new(move |host| {
                Box::pin(async move {
                    g.current(&host)?;
                    let mut c = Doc(host.lock_state().config.try_clone()?);
                    let records = c
                        .array("shareRemovals")?
                        .into_iter()
                        .filter(|r| r.s("requestId").as_deref() != Some(&request))
                        .collect();
                    c.set("shareRemovals", Doc::list(records)?)?;
                    workflow::save(&host, g, Save::Config, c, vec![]).await?;
                    Doc::object()
                })
            }),
        )
        .await?;
        Ok(())
    }
    .await;
    let mut out = Doc::json(
        json!({"requestId":request,"localRevoked":true,"cloudSynced":work.is_ok(),"filesDeleted":false}),
    )?;
    if let Err(e) = work {
        out.put("error", json!(e.message))?;
    }
    Ok(out)
}
async fn remove(host: &Arc<Host>, mut guard: Guard, action: &str, input: Doc) -> Result<Doc> {
    if action == "remove-prepare" {
        return preview(host, &guard, &input).await;
    }
    if action == "removals" {
        input.fields(&[])?;
        let pending = Doc(host.lock_state().config.try_clone()?).array("shareRemovals")?;
        for p in pending.into_iter().take(4) {
            let _ = synchronize(host, &guard, p.req("requestId")?).await?;
        }
        let records = Doc(host.lock_state().config.try_clone()?)
            .array("shareRemovals")?
            .into_iter()
            .map(|r| {
                let mut d = Doc::object()?;
                for k in ["requestId", "connectionId", "folders"] {
                    d.set(k, r.need(k)?)?;
                }
                Ok(d)
            })
            .collect::<Result<_>>()?;
        let mut out = Doc::json(json!({"filesDeleted":false}))?;
        out.set("pending", Doc::list(records)?)?;
        return Ok(out);
    }
    input.fields(&["requestId", "snapshotDigest", "confirmation"])?;
    let request = id(&input, "requestId", 32)?;
    if input.s("confirmation").as_deref() != Some("remove-shares-keep-files-v1") {
        return Err(Error::new(400, "请确认移除共享；磁盘文件保留。"));
    }
    let pending = Doc(host.lock_state().config.try_clone()?)
        .array("shareRemovals")?
        .into_iter()
        .find(|r| r.s("requestId").as_deref() == Some(&request));
    if let Some(pending) = pending {
        if pending.s("snapshotDigest") != input.s("snapshotDigest") {
            return Err(workflow::stale());
        }
    } else {
        let p = host
            .workflows
            .inner
            .lock()
            .unwrap()
            .previews
            .get(&request)
            .map(Doc::copy)
            .transpose()?
            .ok_or_else(workflow::stale)?;
        if p.s("snapshotDigest") != input.s("snapshotDigest")
            || p.n("until").is_none_or(|t| t < crate::management::now())
        {
            return Err(workflow::stale());
        }
        let remote = connections(host, &guard).await?;
        if !remote.array("connections")?.iter().any(|c| {
            c.s("connectionId") == p.s("connectionId") && c.n("revision") == p.n("expectedRevision")
        }) {
            return Err(workflow::stale());
        }
        let g = guard.clone();
        workflow::commit(
            host,
            Box::new(move |host| {
                Box::pin(async move {
                    g.current(&host)?;
                    if Some(removal_policy(&host)?) != p.s("policy") {
                        return Err(workflow::stale());
                    }
                    let mut c = Doc(host.lock_state().config.try_clone()?);
                    let mut removals = c.array("shareRemovals")?;
                    if removals
                        .iter()
                        .any(|r| r.s("requestId") == p.s("requestId"))
                    {
                        return Doc::object();
                    }
                    if removals.len() >= 32 {
                        return Err(Error::new(429, "有撤销待同步，请稍后再试。"));
                    }
                    let ids = p
                        .array("folders")?
                        .into_iter()
                        .map(|r| r.req("rootId"))
                        .collect::<Result<Vec<_>>>()?;
                    let connection = p.req("connectionId")?;
                    let roots = c
                        .array("roots")?
                        .into_iter()
                        .filter(|r| !r.s("id").is_some_and(|s| ids.contains(&s)))
                        .collect();
                    c.set("roots", Doc::list(roots)?)?;
                    let roots = c
                        .array("accountRoots")?
                        .into_iter()
                        .filter(|r| {
                            !(r.s("connectionId").as_deref() == Some(&connection)
                                && r.s("id").is_some_and(|s| ids.contains(&s)))
                        })
                        .collect();
                    c.set("accountRoots", Doc::list(roots)?)?;
                    let grants = c
                        .array("terminalGrants")?
                        .into_iter()
                        .filter(|r| {
                            !(r.s("connectionId").as_deref() == Some(&connection)
                                && r.s("rootId").is_some_and(|s| ids.contains(&s)))
                        })
                        .collect();
                    c.set("terminalGrants", Doc::list(grants)?)?;
                    let mut record = Doc::object()?;
                    for k in ["requestId", "snapshotDigest", "connectionId"] {
                        record.set(k, p.need(k)?)?;
                    }
                    record.put("rootIds", json!(ids))?;
                    for k in ["expectedRevision", "origin", "deviceId", "folders"] {
                        record.set(k, p.need(k)?)?;
                    }
                    removals.push(record);
                    c.set("shareRemovals", Doc::list(removals)?)?;
                    let mut managed = c
                        .array("managedConnections")?
                        .into_iter()
                        .filter(|r| r.s("connectionId").as_deref() != Some(&connection))
                        .collect::<Vec<_>>();
                    let mut entry = Doc::object()?;
                    for k in ["connectionId", "deviceId", "origin"] {
                        entry.set(k, p.need(k)?)?;
                    }
                    managed.push(entry);
                    c.set("managedConnections", Doc::list(managed)?)?;
                    change_policy(&host, g, c).await?;
                    host.terminal.stop_roots(&connection, &ids);
                    Doc::object()
                })
            }),
        )
        .await?;
        guard.policy = workflow::policy(&host.lock_state());
    }
    synchronize(host, &guard, request).await
}
async fn terminal_action(host: &Arc<Host>, guard: &Guard, action: &str, input: Doc) -> Result<Doc> {
    if action == "permissions" {
        input.fields(&[])?;
        let mut list = connections(host, guard).await?;
        list.put("sandboxed", json!(false))?;
        return Ok(list);
    }
    input.fields(&["connectionId", "rootId", "enabled", "confirmation"])?;
    let connection = id(&input, "connectionId", 32)?;
    let root = input.req("rootId")?;
    let enabled = crate::value::boolean(&input.0, crate::value::prop(&input.0, "enabled"))
        .ok_or_else(|| Error::new(400, "Explicit boolean required."))?;
    if enabled && input.s("confirmation").as_deref() != Some("allow-unsandboxed-terminal-v1") {
        return Err(Error::new(
            400,
            "请明确确认终端以系统用户权限运行，不是目录沙箱。",
        ));
    }
    let selected = connections(host, guard)
        .await?
        .array("connections")?
        .into_iter()
        .find(|c| c.s("connectionId").as_deref() == Some(&connection))
        .ok_or_else(|| Error::new(403, "Connection not locally authorized."))?;
    let remote = selected
        .array("roots")?
        .into_iter()
        .find(|r| r.s("rootId").as_deref() == Some(&root) && r.b("locallyPresent"))
        .ok_or_else(workflow::stale)?;
    if enabled && remote.s("mode").as_deref() != Some("direct") {
        return Err(Error::new(403, "Terminal requires a direct shared folder."));
    }
    let scope = scopes(&selected.need("scopes")?)?
        .iter()
        .any(|s| s == "terminal:execute");
    let g = guard.clone();
    workflow::commit(host,Box::new(move|host|Box::pin(async move{g.current(&host)?;let mut c=Doc(host.lock_state().config.try_clone()?);let mut roots=c.array("roots")?;roots.extend(c.array("accountRoots")?);if !roots.iter().any(|r|r.s("id").as_deref()==Some(&root)&&(!enabled||r.mode().is_ok_and(|m|m=="direct"))){return Err(workflow::stale());}let mut grants=c.array("terminalGrants")?.into_iter().filter(|r|!(r.s("connectionId").as_deref()==Some(&connection)&&r.s("rootId").as_deref()==Some(&root))).collect::<Vec<_>>();if enabled{let origin=crate::tools::identity(&host.lock_state().secrets)?.origin;let mut grant=Doc::object()?;grant.put("connectionId",json!(connection))?;grant.put("rootId",json!(root))?;grant.put("resource",json!(format!("{origin}/mcp")))?;grant.put("enabled",json!(true))?;grants.push(grant);}c.set("terminalGrants",Doc::list(grants)?)?;change_policy(&host,g,c).await?;Doc::json(json!({"saved":true,"enabled":enabled,"oauthScopeGranted":scope,"sandboxed":false}))}))).await
}
pub async fn handle(host: &Arc<Host>, request: Request, input: Doc) -> Result<Reply> {
    let target = request.target.clone();
    let action = target.rsplit('/').next().unwrap_or("").to_owned();
    let terminal = target.starts_with("/api/terminal/");
    let allow_paused = matches!(
        action.as_str(),
        "connections" | "remove-prepare" | "remove-confirm" | "removals" | "permissions"
    );
    let mut guard = Guard::capture(host, request.disconnected, allow_paused)?;
    guard.credential = Some((
        Slot::Active,
        crate::tools::identity(&host.lock_state().secrets)?,
    ));
    if action == "connections" {
        input.fields(&[])?;
    }
    if terminal && !["permissions", "set-permission"].contains(&action.as_str()) {
        return Err(Error::new(404, "Unknown terminal management action."));
    }
    if !terminal
        && !matches!(
            action.as_str(),
            "connections"
                | "prepare"
                | "confirm"
                | "status"
                | "resume"
                | "remove-prepare"
                | "remove-confirm"
                | "removals"
        )
    {
        return Err(Error::new(404, "Unknown shared folder action."));
    }
    if !terminal && matches!(action.as_str(), "prepare" | "confirm" | "status" | "resume") {
        input.fields(if action == "prepare" {
            &["requestId", "connectionId", "folders", "accessProfile"]
        } else if action == "confirm" {
            &["requestId", "snapshotDigest", "confirmation"]
        } else {
            &["requestId"]
        })?;
        id(&input, "requestId", 32)?;
    }
    let key = format!(
        "management:{}",
        input
            .s("requestId")
            .map(|id| if action == "status" {
                format!("status:{id}")
            } else {
                id
            })
            .unwrap_or_else(|| format!(
                "{action}:{}:{}",
                input.s("connectionId").unwrap_or_default(),
                input.s("rootId").unwrap_or_default()
            ))
    );
    let fingerprint = Doc::list(vec![Doc::json(json!(action))?, input.copy()?])?.digest()?;
    let owner = host.clone();
    let result = host
        .workflows
        .coalesce(host, key, fingerprint, 8, async move {
            if action == "connections" {
                connections(&owner, &guard).await
            } else if terminal {
                terminal_action(&owner, &guard, &action, input).await
            } else if action.starts_with("remove") || action == "removals" {
                remove(&owner, guard, &action, input).await
            } else {
                manage(&owner, &guard, &action, input).await
            }
        })
        .await?;
    workflow::reply(result)
}

// Retry only durable revocations, with the original request ID. This task owns no
// new authorization and remains supervised until its actual network/save tail ends.
pub async fn retry_removals(host: std::sync::Weak<Host>) {
    let Some(owner) = host.upgrade() else { return };
    let mut closed = owner.bridge_stop.subscribe();
    if *closed.borrow() {
        return;
    }
    drop(owner);
    loop {
        tokio::select! {
            _ = closed.changed() => return,
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
        }
        let Some(owner) = host.upgrade() else { return };
        if owner.faulted() || owner.closing.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let work = async {
            if Doc(owner.lock_state().config.try_clone()?)
                .array("shareRemovals")?
                .is_empty()
            {
                return Doc::object();
            }
            let (_connected, disconnected) = tokio::sync::watch::channel(false);
            let mut guard = Guard::capture(&owner, disconnected, true)?;
            guard.credential = Some((
                Slot::Active,
                crate::tools::identity(&owner.lock_state().secrets)?,
            ));
            let input = Doc::object()?;
            let fingerprint =
                Doc::list(vec![Doc::json(json!("removals"))?, input.copy()?])?.digest()?;
            let task_owner = owner.clone();
            owner
                .workflows
                .coalesce(
                    &owner,
                    "management:removals::".into(),
                    fingerprint,
                    8,
                    async move {
                        let _connected = _connected;
                        remove(&task_owner, guard, "removals", input).await
                    },
                )
                .await
        }
        .await;
        // A failed synchronization leaves the saved restriction intact for retry.
        let _ = work;
    }
}
