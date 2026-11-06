//! Local consent only. Checked directory handles survive through actual publication.
use crate::{Error, Reply, Result, persistence::confirmed, root_mode, runtime::Host, value};
use chat2local_agent_platform::FolderBrowse;
use chat2local_js_value_compat::{Document, Value as J, ValueId};
use serde_json::json;
use std::{
    path::Path,
    sync::{Arc, atomic::Ordering},
};
use tokio::sync::watch;

fn stale() -> Error {
    Error::new(409, "本机状态或目录选择已变化，没有新增授权。")
}
pub fn identifier(s: Option<String>) -> Result<String> {
    s.filter(|s| {
        s.len() == 36
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
    })
    .ok_or_else(|| Error::new(400, "Invalid identifier."))
}
fn mode(s: Option<String>) -> Result<String> {
    s.filter(|s| ["read-only", "review", "direct"].contains(&s.as_str()))
        .ok_or_else(|| Error::new(400, "Invalid folder permission."))
}
pub fn permission(input: &Document) -> Result<String> {
    let m = value::prop(input, "writeMode");
    let w = value::prop(input, "write");
    if m.is_some() && w.is_some() {
        return Err(Error::new(400, "Ambiguous folder permission."));
    }
    let selected = if m.is_some() {
        mode(value::string(input, m))?
    } else {
        match value::boolean(input, w) {
            Some(true) => "review",
            Some(false) => "read-only",
            None => return Err(Error::new(400, "An explicit boolean is required.")),
        }
        .into()
    };
    let confirm = value::prop(input, "confirmDirect");
    if confirm.is_some() && value::boolean(input, confirm).is_none() {
        return Err(Error::new(400, "An explicit boolean is required."));
    }
    if selected == "direct" && value::boolean(input, confirm) != Some(true) {
        return Err(Error::new(
            400,
            "请明确确认：此目录允许直接创建和修改文件，不再逐次要求本机审批。",
        ));
    }
    Ok(selected)
}
fn subtree(config: &Document, id: ValueId) -> Result<Document> {
    value::parse(value::subtree(config, id)?.as_bytes())
}
fn field(doc: &mut Document, key: &str, child: Document) -> Result<()> {
    let id = doc.import(child, usize::MAX)?;
    doc.set_property(doc.root(), key.encode_utf16().collect(), id)?;
    Ok(())
}
fn set_permission(root: &mut Document, selected: &str) -> Result<()> {
    value::put(root, "write", J::Bool(selected != "read-only"))?;
    value::put(root, "writeMode", value::text(selected))
}
fn roots(config: &Document) -> Vec<ValueId> {
    value::array(config, value::prop(config, "roots")).unwrap_or_default()
}
fn existing(config: &Document, checked: &FolderBrowse) -> Result<Option<ValueId>> {
    for id in roots(config) {
        let path = value::string(config, value::get(config, id, "path")).ok_or_else(stale)?;
        match checked.directory.same_checked(Path::new(&path)) {
            Ok(true) => return Ok(Some(id)),
            Ok(false) => {}
            Err(e) if ["ENOENT", "ENOTDIR"].contains(&e.code) => {}
            Err(e) => {
                return Err(Error::new(
                    400,
                    format!("Directory identity could not be verified ({}).", e.code),
                ));
            }
        }
    }
    Ok(None)
}
fn replace(config: &mut Document, previous: Option<ValueId>, root: Document) -> Result<()> {
    let list = value::prop(config, "roots").ok_or_else(stale)?;
    let selected = config.import(root, usize::MAX)?;
    if let Some(previous) = previous {
        let items = roots(config)
            .into_iter()
            .map(|id| if id == previous { selected } else { id })
            .collect();
        value::put(config, "roots", J::Array(items))?;
    } else {
        config.push(list, selected)?;
    }
    Ok(())
}
pub async fn execute(
    host: &Arc<Host>,
    route: &str,
    input: Document,
    disconnected: watch::Receiver<bool>,
    selection: Option<u64>,
) -> Result<Reply> {
    let set = route == "/api/root/set-mode";
    let authorize = route == "/api/guide/authorize";
    let cancel = route == "/api/guide/cancel";
    value::fields(
        &input,
        if set {
            &["id", "writeMode", "expectedWriteMode", "confirmDirect"]
        } else if authorize {
            &[
                "path",
                "expectedRootId",
                "expectedWriteMode",
                "requestId",
                "confirmDirect",
            ]
        } else if cancel {
            &["attemptId"]
        } else {
            &["path", "write", "writeMode", "confirmDirect"]
        },
    )?;
    let selected = if authorize {
        if value::boolean(&input, value::prop(&input, "confirmDirect")) != Some(true) {
            return Err(Error::new(
                400,
                "请点击明确标注的“允许读写并继续”完成此次目录授权。",
            ));
        }
        "direct".into()
    } else if cancel {
        String::new()
    } else {
        permission(&input)?
    };
    let (mut next, epoch, revision) = {
        let state = host.lock_state();
        if !set
            && !cancel
            && value::boolean(&state.config, value::prop(&state.config, "paused")) == Some(true)
        {
            return Err(stale());
        }
        (state.config.try_clone()?, state.epoch, selection)
    };
    let mut checked = None;
    let mut event = None;
    let mut reply;
    if cancel {
        let id = identifier(value::string(&input, value::prop(&input, "attemptId")))?;
        if value::prop(&next, "connectionGuide")
            .and_then(|g| value::string(&next, value::get(&next, g, "id")))
            .as_deref()
            != Some(&id)
        {
            return Err(Error::new(409, "接入步骤已变化，请刷新后再取消。"));
        }
        value::remove(&mut next, "connectionGuide")?;
        reply = value::parse(br#"{"cancelled":true,"permissionsPreserved":true}"#)?;
    } else {
        let previous = if set {
            let id = identifier(value::string(&input, value::prop(&input, "id")))?;
            let found = roots(&next)
                .into_iter()
                .find(|r| value::string(&next, value::get(&next, *r, "id")).as_deref() == Some(&id))
                .ok_or_else(|| Error::new(404, "Folder is not authorized."))?;
            if root_mode(&next, found)?
                != mode(value::string(
                    &input,
                    value::prop(&input, "expectedWriteMode"),
                ))?
            {
                return Err(Error::new(409, "目录权限已在其他页面改变，请刷新后重试。"));
            }
            Some(found)
        } else {
            None
        };
        let path = if let Some(id) = previous {
            value::string(&next, value::get(&next, id, "path"))
        } else {
            value::string(&input, value::prop(&input, "path"))
        }
        .ok_or_else(|| Error::new(400, "Choose an absolute local folder."))?;
        let directory = host.store.directory().to_owned();
        let held = Arc::new(
            tokio::task::spawn_blocking(move || {
                let held = FolderBrowse::open(Some(&path), &directory)
                    .map_err(|e| Error::new(400, e.message))?;
                if !held
                    .selectable_checked()
                    .map_err(|e| Error::new(400, e.message))?
                {
                    return Err(Error::new(
                        400,
                        "Do not authorize an entire drive, user profile or protected directory.",
                    ));
                }
                Ok(held)
            })
            .await
            .map_err(|_| Error::new(503, "Directory verification failed."))??,
        );
        #[cfg(feature = "fixture")]
        host.hooks.wait_async("consent:checked").await;
        let previous = if set {
            previous
        } else {
            existing(&next, &held)?
        };
        if !set
            && !authorize
            && let Some(id) = previous
        {
            let mut existing = subtree(&next, id)?;
            value::put(
                &mut existing,
                "writeMode",
                value::text(&root_mode(&next, id)?),
            )?;
            value::put(&mut existing, "alreadyAuthorized", J::Bool(true))?;
            ensure(host, epoch, revision, &disconnected, false)?;
            return document(existing);
        }
        let request = if authorize {
            Some(identifier(value::string(
                &input,
                value::prop(&input, "requestId"),
            ))?)
        } else {
            None
        };
        if let Some(request) = &request {
            if let Some(g) = value::prop(&next, "connectionGuide")
                && value::string(&next, value::get(&next, g, "id")).as_deref() == Some(request)
            {
                if !previous.is_some_and(|r| {
                    root_mode(&next, r).is_ok_and(|m| m == "direct")
                        && value::string(&next, value::get(&next, r, "id"))
                            == value::string(&next, value::get(&next, g, "rootId"))
                }) {
                    return Err(Error::new(409, "此次接入已失效，没有重新授权。"));
                }
                ensure(host, epoch, revision, &disconnected, false)?;
                return crate::guide::view(host);
            }
            if let Some(p) = previous {
                if value::string(&input, value::prop(&input, "expectedRootId"))
                    != value::string(&next, value::get(&next, p, "id"))
                    || value::string(&input, value::prop(&input, "expectedWriteMode")).as_deref()
                        != Some(&root_mode(&next, p)?)
                {
                    return Err(Error::new(
                        409,
                        "目录授权已变化。请重新选择并查看当前权限，没有自动升级。",
                    ));
                }
            } else if !["expectedRootId", "expectedWriteMode"].iter().all(|k| {
                value::prop(&input, k).is_some_and(|id| matches!(input.value(id), Ok(J::Null)))
            }) {
                return Err(Error::new(409, "原目录授权已移除，请重新选择。"));
            }
        }
        if previous.is_none() && roots(&next).len() >= 50 {
            return Err(Error::new(400, "At most 50 folders may be authorized."));
        }
        let mut root=match previous {Some(id)=>subtree(&next,id)?,None=>value::parse(json!({"id":crate::uuid()?,"label":held.directory.path.file_name().and_then(|s|s.to_str()).ok_or_else(stale)?,"path":held.directory.path.to_str().ok_or_else(stale)?,"write":selected!="read-only"}).to_string().as_bytes())?};
        set_permission(&mut root, &selected)?;
        let id = value::string(&root, value::prop(&root, "id")).ok_or_else(stale)?;
        if set
            || authorize
                && previous.is_none_or(|p| root_mode(&next, p).is_ok_and(|m| m != "direct"))
        {
            let from = previous
                .map(|p| root_mode(&next, p))
                .transpose()?
                .unwrap_or("not-authorized".into());
            event = Some((
                if set {
                    "permission-changed"
                } else {
                    "directory-consent"
                },
                if set {
                    json!({"rootId":id,"from":from,"to":selected})
                } else {
                    json!({"rootId":id,"from":from,"to":"direct","flow":"connection-guide"})
                },
            ));
        }
        reply = root.try_clone()?;
        replace(&mut next, previous, root)?;
        if let Some(request) = request {
            field(&mut next,"connectionGuide",value::parse(json!({"version":1,"id":request,"rootId":id,"startedAt":crate::tools::iso_now(),"evidence":{}}).to_string().as_bytes())?)?;
        }
        checked = Some(held);
    }
    if !authorize && !cancel {
        let revision =
            value::number(&next, value::prop(&next, "accountPolicyRevision")).unwrap_or(0.0) + 1.0;
        value::put(&mut next, "accountPolicyRevision", J::Number(revision))?;
        if set && let Some(g) = value::prop(&next, "connectionGuide") {
            let selected_root = value::string(&next, value::get(&next, g, "rootId"));
            if selected_root == value::string(&input, value::prop(&input, "id"))
                && value::string(&input, value::prop(&input, "expectedWriteMode")).as_deref()
                    != Some(&selected)
            {
                value::remove(&mut next, "connectionGuide")?;
            }
        }
    }
    let cancel_proposals = !cancel && (!authorize || event.is_some());
    let owner = host.clone();
    let expected = epoch;
    let disconnected_copy = disconnected.clone();
    let receive = host.persistence.submit(move |store| {
        let _held = checked;
        store
            .save_config_scoped(&next, &|publish| {
                #[cfg(feature = "fixture")]
                owner.hooks.wait("consent:publish");
                let _core = owner.core.lock().unwrap_or_else(|e| e.into_inner());
                let mut state = owner.lock_state();
                let disconnected = disconnected_copy.borrow();
                owner
                    .platform
                    .with_selection(revision, |selection_current| {
                        if owner.faulted()
                            || owner.closing.load(Ordering::SeqCst)
                            || state.epoch != expected
                            || *disconnected
                            || !selection_current
                            || (!set
                                && !cancel
                                && value::boolean(
                                    &state.config,
                                    value::prop(&state.config, "paused"),
                                ) == Some(true))
                        {
                            return Err(chat2local_native_store::Error::new(
                                "ECANCELLED",
                                "Consent authority changed before publication.",
                            ));
                        }
                        // Prepare memory before publication; no fallible copy after commit.
                        let installed = next.try_clone().map_err(|e| {
                            chat2local_native_store::Error::new("EINVALID", e.to_string())
                        })?;
                        publish()?;
                        state.config = installed;
                        state.epoch += 1;
                        if cancel_proposals {
                            crate::operations::cancel_pending(&mut state);
                        }
                        state.guide_warning = None;
                        Ok(())
                    })
            })
            .map_err(|e| {
                if e.code == "ECANCELLED" {
                    stale()
                } else {
                    Error::new(
                        503,
                        format!("Consent persistence completion is not confirmed: {e}"),
                    )
                }
            })
    })?;
    confirmed(receive, false).await?;
    if let Some((action, details)) = event
        && crate::operations::audit(host, action, details)
            .await
            .is_err()
    {
        let warning = if authorize {
            "目录授权已保存，但操作日志写入失败。"
        } else {
            "权限已保存，但操作日志写入失败，请检查本机存储。"
        };
        if authorize {
            host.lock_state().guide_warning = Some(warning.into());
        } else {
            value::put(&mut reply, "warning", value::text(warning))?;
        }
    }
    if authorize {
        crate::guide::view(host)
    } else {
        document(reply)
    }
}
fn ensure(
    host: &Host,
    epoch: u64,
    revision: Option<u64>,
    disconnected: &watch::Receiver<bool>,
    allow_paused: bool,
) -> Result<()> {
    let _core = host.core.lock().unwrap_or_else(|e| e.into_inner());
    let state = host.lock_state();
    if host.faulted()
        || host.closing.load(Ordering::SeqCst)
        || state.epoch != epoch
        || revision.is_some_and(|r| host.platform.selection_revision() != r)
        || *disconnected.borrow()
        || !allow_paused
            && value::boolean(&state.config, value::prop(&state.config, "paused")) == Some(true)
    {
        return Err(stale());
    }
    Ok(())
}
pub fn document(doc: Document) -> Result<Reply> {
    Ok(Reply {
        content_type: "application/json; charset=utf-8",
        status: 200,
        body: value::serialized(&doc)?,
        cookie: None,
    })
}
