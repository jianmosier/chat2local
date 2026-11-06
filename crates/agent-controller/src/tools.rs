use crate::{
    Error, Result,
    persistence::confirmed,
    root_mode,
    runtime::{Host, State},
    value,
};
use chat2local_js_value_compat::{Document, Value};
use chat2local_protocol::{Access, Request};
use serde_json::json;
use std::{
    collections::HashSet,
    sync::{Arc, atomic::Ordering},
};

#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub origin: String,
    pub device: String,
    pub key: String,
}
fn denied() -> Error {
    Error::new(
        403,
        "Current folder/device/connection authorization does not permit this operation.",
    )
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn root_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
fn canonical_resource(s: &str) -> bool {
    if s.encode_utf16().count() > 2048 {
        return false;
    }
    url::Url::parse(s).is_ok_and(|u| {
        u.as_str() == s
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && u.path() == "/mcp"
            && (u.scheme() == "https"
                || (u.scheme() == "http"
                    && matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))))
    })
}
pub fn identity(secrets: &Document) -> Result<Identity> {
    let id = value::prop(secrets, "identity").ok_or_else(denied)?;
    let get = |key| value::string(secrets, value::get(secrets, id, key)).ok_or_else(denied);
    let identity = Identity {
        origin: get("origin")?,
        device: get("deviceId")?,
        key: get("deviceKey")?,
    };
    if !hex(&identity.device, 32)
        || !hex(&identity.key, 64)
        || !canonical_resource(&(identity.origin.clone() + "/mcp"))
    {
        return Err(denied());
    }
    Ok(identity)
}
pub struct Call {
    pub id: String,
    pub tool: String,
    pub args: Document,
    pub access: Option<Document>,
    pub diagnostics: Option<Box<Document>>,
}
impl Call {
    pub fn copy(&self) -> Result<Self> {
        Ok(Self {
            id: self.id.clone(),
            tool: self.tool.clone(),
            args: self.args.try_clone()?,
            access: self.access.as_ref().map(Document::try_clone).transpose()?,
            diagnostics: self
                .diagnostics
                .as_deref()
                .map(Document::try_clone)
                .transpose()?
                .map(Box::new),
        })
    }

    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() > 512 * 1024 {
            return Err(Error::new(400, "Oversized Bridge frame."));
        }
        let doc = value::parse(raw.as_bytes())?;
        let id = value::string(&doc, value::prop(&doc, "id"))
            .filter(|s| {
                s.len() == 36
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
            })
            .ok_or_else(|| Error::new(400, "Invalid Bridge envelope."))?;
        if value::string(&doc, value::prop(&doc, "kind")).as_deref() != Some("call") {
            return Err(Error::new(400, "Invalid Bridge envelope."));
        }
        let tool = value::string(&doc, value::prop(&doc, "tool")).unwrap_or_default();
        let args = match value::prop(&doc, "args") {
            Some(id) => value::parse(value::subtree(&doc, id)?.as_bytes())?,
            None => value::parse(b"{}")?,
        };
        let access = value::prop(&doc, "connectionAccess")
            .map(|id| value::subtree(&doc, id).and_then(|s| value::parse(s.as_bytes())))
            .transpose()?;
        Ok(Self {
            id,
            tool,
            args,
            access,
            diagnostics: value::prop(&doc, "connectionDiagnostics")
                .map(|id| value::subtree(&doc, id).and_then(|s| value::parse(s.as_bytes())))
                .transpose()?
                .map(Box::new),
        })
    }
}
pub(crate) fn access(call: &Call, identity: &Identity) -> Result<Option<Access>> {
    let Some(doc) = &call.access else {
        return Ok(None);
    };
    value::fields(
        doc,
        &[
            "version",
            "connectionId",
            "deviceId",
            "resource",
            "roots",
            "scopes",
        ],
    )?;
    let access: Access = serde_json::from_str(&value::serialized(doc)?).map_err(|_| denied())?;
    if access.version != 1
        || !hex(&access.connection_id, 32)
        || !hex(&access.device_id, 32)
        || access.device_id != identity.device
        || access.resource != identity.origin.clone() + "/mcp"
        || !canonical_resource(&access.resource)
        || access.roots.is_empty()
        || access.roots.len() > 50
        || access.roots.iter().any(|r| !root_id(&r.root_id))
        || access
            .roots
            .iter()
            .map(|r| &r.root_id)
            .collect::<HashSet<_>>()
            .len()
            != access.roots.len()
        || access.scopes.len() > 4
        || !access.scopes.iter().any(|s| s == "files:read")
        || access.scopes.iter().collect::<HashSet<_>>().len() != access.scopes.len()
        || access.scopes.iter().any(|s| {
            ![
                "files:read",
                "files:write",
                "files:propose",
                "terminal:execute",
            ]
            .contains(&s.as_str())
        })
    {
        return Err(denied());
    }
    Ok(Some(access))
}
fn mode(mode: &chat2local_protocol::Mode) -> &'static str {
    match mode {
        chat2local_protocol::Mode::ReadOnly => "read-only",
        chat2local_protocol::Mode::Review => "review",
        chat2local_protocol::Mode::Direct => "direct",
    }
}
pub(crate) fn effective(local: &str, access: Option<&Access>, id: &str) -> Option<String> {
    let Some(a) = access else {
        return Some(local.to_owned());
    };
    let share = a.roots.iter().find(|s| s.root_id == id)?;
    Some(
        if local == "read-only" || mode(&share.mode) == "read-only" {
            "read-only"
        } else if local == "direct"
            && mode(&share.mode) == "direct"
            && a.scopes.iter().any(|s| s == "files:write")
        {
            "direct"
        } else if a.scopes.iter().any(|s| s == "files:propose") {
            "review"
        } else {
            "read-only"
        }
        .to_owned(),
    )
}
pub fn description() -> Result<serde_json::Value> {
    let name = chat2local_agent_platform::computer_name()
        .map_err(|_| Error::new(503, "Computer metadata unavailable."))?;
    let mut description = json!({"name":name,"platform":std::env::consts::OS.replace("windows","win32"),"arch":if cfg!(target_arch="x86_64"){"x64"}else{std::env::consts::ARCH},"system":if cfg!(windows){"Windows"}else{std::env::consts::OS}});
    description.as_object_mut().unwrap().retain(|_, value| {
        value.as_str().is_some_and(|text| {
            !text.is_empty()
                && text.encode_utf16().count() <= 128
                && !text.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
        })
    });
    Ok(description)
}
fn device(state: &State, id: &Identity) -> Result<Document> {
    let mut d = value::parse(description()?.to_string().as_bytes())?;
    value::put(&mut d, "deviceId", value::text(&id.device))?;
    if let Some(i) = value::prop(&state.config, "installationId") {
        let i = d.import(
            value::parse(value::subtree(&state.config, i)?.as_bytes())?,
            usize::MAX,
        )?;
        d.set_property(d.root(), "installationId".encode_utf16().collect(), i)?;
    }
    Ok(d)
}
pub struct Prepared {
    pub fingerprint: String,
    pub immediate: Option<String>,
    pub request: Option<Request>,
}
pub fn prepare(state: &State, call: &Call) -> Result<Prepared> {
    let identity = identity(&state.secrets)?;
    let access = access(call, &identity)?;
    if call.tool != "operation_status"
        && value::boolean(&state.config, value::prop(&state.config, "paused")) != Some(false)
    {
        return Err(Error::new(403, "Local access is paused."));
    }
    validate(call)?;
    if let Some(id) = value::prop(&call.args, "deviceId")
        && value::string(&call.args, Some(id)).as_deref() != Some(&identity.device)
    {
        return Err(denied());
    }
    let roots = value::array(&state.config, value::prop(&state.config, "roots"))
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r, false))
        .chain(
            value::array(&state.config, value::prop(&state.config, "accountRoots"))
                .unwrap_or_default()
                .into_iter()
                .filter(|r| {
                    access.as_ref().is_some_and(|a| {
                        value::string(&state.config, value::get(&state.config, *r, "connectionId"))
                            .as_deref()
                            == Some(&a.connection_id)
                    })
                })
                .map(|r| (r, true)),
        )
        .collect::<Vec<_>>();
    let mut fingerprint = String::new();
    for key in ["paused", "roots", "accountRoots", "terminalGrants"] {
        fingerprint.push_str(
            &value::prop(&state.config, key)
                .map(|i| value::subtree(&state.config, i))
                .transpose()?
                .unwrap_or_default(),
        );
        fingerprint.push('\n');
    }
    fingerprint.push_str(&identity.origin);
    fingerprint.push_str(&identity.device);
    fingerprint.push_str(&identity.key);
    let mut immediate = None;
    let mut request = None;
    if call.tool == "list_devices" {
        let mut d = device(state, &identity)?;
        value::put(&mut d, "status", value::text("online"))?;
        let mut out = value::parse(br#"{"devices":[],"selectionRequired":false}"#)?;
        let d = out.import(d, usize::MAX)?;
        out.push(value::prop(&out, "devices").unwrap(), d)?;
        immediate = Some(value::serialized(&out)?);
    } else if call.tool == "list_roots" {
        let mut out = value::parse(b"[]")?;
        for (root, _) in roots {
            let id = value::string(&state.config, value::get(&state.config, root, "id"))
                .ok_or_else(denied)?;
            let Some(mode) = effective(&root_mode(&state.config, root)?, access.as_ref(), &id)
            else {
                continue;
            };
            let mut row=value::parse(json!({"id":id,"writeMode":mode,"writeProposalsAllowed":mode!="read-only","directWriteAllowed":mode=="direct","terminalAllowed":false,"terminalStatus":"unavailable","terminalSandboxed":false}).to_string().as_bytes())?;
            if let Some(label) = value::get(&state.config, root, "label") {
                let label = row.import(
                    value::parse(value::subtree(&state.config, label)?.as_bytes())?,
                    usize::MAX,
                )?;
                row.set_property(row.root(), "label".encode_utf16().collect(), label)?;
            }
            let local = value::array(&state.config, value::prop(&state.config, "terminalGrants"))
                .unwrap_or_default()
                .iter()
                .any(|g| {
                    value::boolean(&state.config, value::get(&state.config, *g, "enabled"))
                        == Some(true)
                        && value::string(&state.config, value::get(&state.config, *g, "rootId"))
                            .as_deref()
                            == Some(&id)
                        && access.as_ref().is_some_and(|a| {
                            value::string(
                                &state.config,
                                value::get(&state.config, *g, "connectionId"),
                            )
                            .as_deref()
                                == Some(&a.connection_id)
                                && value::string(
                                    &state.config,
                                    value::get(&state.config, *g, "resource"),
                                )
                                .as_deref()
                                    == Some(&a.resource)
                        })
                });
            let scope = access
                .as_ref()
                .is_some_and(|a| a.scopes.iter().any(|s| s == "terminal:execute"));
            let available = state.terminal_available && access.is_some();
            value::put(
                &mut row,
                "terminalAllowed",
                Value::Bool(available && mode == "direct" && local && scope),
            )?;
            value::put(
                &mut row,
                "terminalStatus",
                value::text(if !available || mode != "direct" {
                    "unavailable"
                } else if !local {
                    "disabled"
                } else if !scope {
                    "authorization-required"
                } else {
                    "allowed"
                }),
            )?;
            value::put(&mut row, "terminalLocalEnabled", Value::Bool(local))?;
            value::put(
                &mut row,
                "terminalScopeGranted",
                Value::Bool(
                    access
                        .as_ref()
                        .is_some_and(|a| a.scopes.iter().any(|s| s == "terminal:execute")),
                ),
            )?;
            let d = row.import(device(state, &identity)?, usize::MAX)?;
            row.set_property(row.root(), "device".encode_utf16().collect(), d)?;
            let row = out.import(row, usize::MAX)?;
            out.push(out.root(), row)?;
        }
        immediate = Some(value::serialized(&out)?);
    } else if call.tool != "operation_status" {
        let id = value::string(&call.args, value::prop(&call.args, "rootId"))
            .filter(|s| root_id(s))
            .ok_or_else(denied)?;
        let path = value::string(&call.args, value::prop(&call.args, "path"))
            .or_else(|| {
                (call.tool == "list_directory" || call.tool.starts_with("terminal_"))
                    .then(|| ".".into())
            })
            .ok_or_else(denied)?;
        let (root, account) = roots
            .into_iter()
            .find(|(r, _)| {
                value::string(&state.config, value::get(&state.config, *r, "id")).as_deref()
                    == Some(&id)
            })
            .ok_or_else(denied)?;
        let local = root_mode(&state.config, root)?;
        let permitted = effective(&local, access.as_ref(), &id).ok_or_else(denied)?;
        if call.tool == "write_file" && permitted != "direct"
            || call.tool == "propose_write" && permitted == "read-only"
        {
            return Err(denied());
        }
        if call.tool.starts_with("terminal_") {
            let a = access.as_ref().ok_or_else(denied)?;
            if local != "direct"
                || !a
                    .roots
                    .iter()
                    .any(|r| r.root_id == id && matches!(r.mode, chat2local_protocol::Mode::Direct))
                || !a.scopes.iter().any(|s| s == "terminal:execute")
                || !terminal_grant(state, a, &id)
            {
                return Err(denied());
            }
        }
        let access_json = call
            .access
            .as_ref()
            .map(value::serialized)
            .transpose()?
            .unwrap_or_else(|| "null".into());
        let authority = json!({"paused":false,"deviceId":identity.device,"resource":identity.origin+"/mcp","root":{"id":id,"path":value::string(&state.config,value::get(&state.config,root,"path")).ok_or_else(denied)?,"kind":if account{"account"}else{"legacy"},"connectionId":if account{value::string(&state.config,value::get(&state.config,root,"connectionId"))}else{None},"writeMode":local},"access":serde_json::from_str::<serde_json::Value>(&access_json).map_err(|_|denied())?});
        let r:Request=serde_json::from_value(json!({"v":1,"id":crate::uuid()?,"op":if call.tool=="list_directory"||call.tool.starts_with("terminal_"){"list_directory"}else{"read_file"},"args":{"rootId":id,"path":path},"authority":authority})).map_err(|_|denied())?;
        chat2local_policy::authorize(&r).map_err(|_| denied())?;
        request = Some(r);
    }
    Ok(Prepared {
        fingerprint,
        immediate,
        request,
    })
}
pub fn current(host: &Host, call: &Call, fingerprint: &str) -> bool {
    !host.faulted()
        && !host.closing.load(Ordering::SeqCst)
        && prepare(&host.lock_state(), call).is_ok_and(|p| p.fingerprint == fingerprint)
}
pub async fn execute(
    host: &Arc<Host>,
    call: &Call,
    socket: &Arc<crate::bridge::Socket>,
) -> Result<(String, String)> {
    let prepared = prepare(&host.lock_state(), call)?;
    let fingerprint = prepared.fingerprint;
    let result = if ["write_file", "propose_write", "operation_status"]
        .contains(&call.tool.as_str())
    {
        crate::operations::execute(host, call, socket, &fingerprint, prepared.request).await?
    } else if call.tool.starts_with("terminal_") {
        crate::terminal::execute(host, call, socket, &fingerprint, prepared.request.unwrap())
            .await?
    } else if let Some(result) = prepared.immediate {
        result
    } else {
        let request = prepared.request.unwrap();
        let owner = host.clone();
        let captured = call.copy()?;
        let expected = fingerprint.clone();
        let socket = socket.clone();
        #[cfg(feature = "fixture")]
        let hooks = host.hooks.clone();
        let result = tokio::task::spawn_blocking(move || {
            #[cfg(feature = "fixture")]
            {
                hooks.wait("read");
                hooks.check("read")?;
            }
            if !socket.current(&owner) || !current(&owner, &captured, &expected) {
                return Err(denied());
            }
            chat2local_agent_platform::execute(&request)
                .map_err(|e| Error::new(400, format!("Filesystem operation failed ({}).", e.code)))
        })
        .await
        .map_err(|_| {
            host.poison();
            Error::new(503, "Native read worker failed.")
        })??;
        result.to_string()
    };
    if !socket.current(host) || !current(host, call, &fingerprint) {
        return Err(denied());
    }
    if call.tool == "read_file" {
        let at = iso_now();
        let root = value::string(&call.args, value::prop(&call.args, "rootId")).unwrap();
        let path = value::string(&call.args, value::prop(&call.args, "path")).unwrap();
        let received = socket.with_current(host,call,&fingerprint,|state|{
            state.audit.execute(&json!({"op":"audit","action":"read","details":{"rootId":root,"path":path},"at":at})).map_err(|_|Error::new(503,"Audit state failed."))?;
            let event = value::parse(
                format!(
                    "{{\"at\":{},\"action\":\"read\",\"rootId\":{},\"path\":{}}}",
                    json!(at),
                    json!(root),
                    json!(path)
                )
                .as_bytes(),
            )?;
            host.persistence.submit(move |store| {
                store.append_audit(&event)?;
                Ok(())
            })
        })?;
        confirmed(received, false).await?;
    }
    if !socket.current(host) || !current(host, call, &fingerprint) {
        return Err(denied());
    }
    let pending = socket.with_current(host, call, &fingerprint, |state| {
        state.last_remote = Some(iso_now());
        let mut next = state.config.try_clone()?;
        let changed = guide_progress(&mut next, &state.secrets, call, &result)?;
        if changed || !value::truthy(&next, value::prop(&next, "remoteUseConfirmed")) {
            value::put(&mut next, "remoteUseConfirmed", Value::Bool(true))?;
            let saved = next.try_clone()?;
            if call.tool.starts_with("terminal_") && !host.terminal.begin_progress() {
                return Ok(None);
            }
            #[cfg(feature = "fixture")]
            let hooks = host.hooks.clone();
            let receive = host.persistence.submit(move |store| {
                #[cfg(feature = "fixture")]
                hooks.check("progress")?;
                store.save_config(&saved)?;
                Ok(())
            });
            Ok(Some((receive, next, state.epoch)))
        } else {
            Ok(None)
        }
    })?;
    if let Some((receive, next, epoch)) = pending {
        let owner = host.clone();
        let captured = call.copy()?;
        let socket = socket.clone();
        let expected = fingerprint.clone();
        let terminal = call.tool.starts_with("terminal_");
        let publication = async move {
            let host = &owner;
            let call = &captured;
            let fingerprint = &expected;
            let outcome = match receive {
                Ok(r) => confirmed(r, false).await,
                Err(e) => Err(e),
            };
            if outcome.is_ok() {
                let _ = socket.with_current(host, call, fingerprint, |state| {
                    if state.epoch == epoch {
                        state.config = next;
                        state.guide_warning = None;
                    }
                    Ok(())
                });
            } else {
                host.lock_state().guide_warning=Some("Remote operation completed, but progress could not be saved. Read back to verify; do not repeat blindly.".into());
            }
            if terminal {
                host.terminal.end_progress();
            }
        };
        // STARTED/status/cancel do not wait for configuration progress. The
        // coalesced continuation and its actual disk tail retain host ownership.
        if terminal {
            tokio::spawn(publication);
        } else {
            publication.await;
        }
    }
    Ok((result, fingerprint))
}
fn guide_progress(
    config: &mut Document,
    secrets: &Document,
    call: &Call,
    result: &str,
) -> Result<bool> {
    if !["read_file", "write_file"].contains(&call.tool.as_str()) {
        return Ok(false);
    }
    let Some(g) = value::prop(config, "connectionGuide") else {
        return Ok(false);
    };
    let Some(id) = value::string(config, value::get(config, g, "id")) else {
        return Ok(false);
    };
    let Some(root) = value::string(config, value::get(config, g, "rootId")) else {
        return Ok(false);
    };
    let valid_id = |s: &str| {
        s.len() == 36
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
    };
    if value::number(config, value::get(config, g, "version")) != Some(1.0)
        || !valid_id(&id)
        || !valid_id(&root)
        || value::string(config, value::get(config, g, "startedAt")).is_none()
        || value::string(&call.args, value::prop(&call.args, "rootId")).as_deref() != Some(&root)
        || value::string(&call.args, value::prop(&call.args, "path")).as_deref()
            != Some(&format!("chat2local-check-{id}.txt"))
    {
        return Ok(false);
    }
    let Some(r) = value::array(config, value::prop(config, "roots"))
        .unwrap_or_default()
        .into_iter()
        .find(|r| value::string(config, value::get(config, *r, "id")).as_deref() == Some(&root))
    else {
        return Ok(false);
    };
    if root_mode(config, r)? != "direct" {
        return Ok(false);
    }
    let identity = identity(secrets)?;
    let bound = value::string(config, value::get(config, g, "deviceId")).as_deref()
        == Some(&identity.device)
        && value::string(config, value::get(config, g, "origin")).as_deref()
            == Some(&identity.origin);
    let mut evidence = if bound {
        value::get(config, g, "evidence")
            .map(|e| value::subtree(config, e).and_then(|s| value::parse(s.as_bytes())))
            .transpose()?
            .unwrap_or(value::parse(b"{}")?)
    } else {
        value::parse(b"{}")?
    };
    use sha2::{Digest, Sha256};
    let created = format!("chat2local connection check\nrequest: {id}\nstage: created\n");
    let updated = format!("chat2local connection check\nrequest: {id}\nstage: updated\n");
    let created_hash = hex::encode(Sha256::digest(created.as_bytes()));
    let updated_hash = hex::encode(Sha256::digest(updated.as_bytes()));
    let result = value::parse(result.as_bytes())?;
    let hash = value::string(&result, value::prop(&result, "sha256"));
    let at = value::text(&iso_now());
    let mut changed = false;
    if call.tool == "write_file"
        && value::string(&result, value::prop(&result, "status")).as_deref() == Some("written")
    {
        let expected = value::prop(&call.args, "expectedHash");
        let content = value::string(&call.args, value::prop(&call.args, "content"));
        if expected.is_some_and(|i| matches!(call.args.value(i), Ok(Value::Null)))
            && content.as_deref() == Some(&created)
            && hash.as_deref() == Some(&created_hash)
        {
            value::put(&mut evidence, "createdAt", at.clone())?;
            value::remove(&mut evidence, "updatedAt")?;
            value::remove(&mut evidence, "readBackAt")?;
            changed = true;
        } else if value::truthy(&evidence, value::prop(&evidence, "createdAt"))
            && value::string(&call.args, expected).as_deref() == Some(&created_hash)
            && content.as_deref() == Some(&updated)
            && hash.as_deref() == Some(&updated_hash)
            && value::boolean(&result, value::prop(&result, "backupSaved")) == Some(true)
        {
            value::put(&mut evidence, "updatedAt", at.clone())?;
            value::remove(&mut evidence, "readBackAt")?;
            changed = true;
        }
    }
    if call.tool == "read_file"
        && value::truthy(&evidence, value::prop(&evidence, "createdAt"))
        && value::truthy(&evidence, value::prop(&evidence, "updatedAt"))
        && value::string(&result, value::prop(&result, "content")).as_deref() == Some(&updated)
        && hash.as_deref() == Some(&updated_hash)
    {
        value::put(&mut evidence, "readBackAt", at)?;
        changed = true;
    }
    if !changed {
        return Ok(false);
    }
    let evidence = config.import(evidence, usize::MAX)?;
    config.set_property(g, "evidence".encode_utf16().collect(), evidence)?;
    for (key, text) in [("deviceId", identity.device), ("origin", identity.origin)] {
        let id = config.add(value::text(&text), usize::MAX)?;
        config.set_property(g, key.encode_utf16().collect(), id)?;
    }
    Ok(true)
}
pub fn iso_now() -> String {
    let ms = crate::management::now() as i64;
    let days = ms / 86400000;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    y += i64::from(m <= 2);
    let second = ms / 1000;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        second / 3600 % 24,
        second / 60 % 60,
        second % 60,
        ms % 1000
    )
}

pub(crate) fn terminal_grant(state: &State, a: &Access, id: &str) -> bool {
    value::array(&state.config, value::prop(&state.config, "terminalGrants"))
        .unwrap_or_default()
        .into_iter()
        .any(|g| {
            value::boolean(&state.config, value::get(&state.config, g, "enabled")) == Some(true)
                && [
                    ("rootId", id),
                    ("connectionId", a.connection_id.as_str()),
                    ("resource", a.resource.as_str()),
                ]
                .iter()
                .all(|(k, v)| {
                    value::string(&state.config, value::get(&state.config, g, k)).as_deref()
                        == Some(*v)
                })
        })
}
fn validate(call: &Call) -> Result<()> {
    let keys: &[&str] = match call.tool.as_str() {
        "list_devices" => &[],
        "list_roots" => &["deviceId"],
        "list_directory" | "read_file" => &["deviceId", "rootId", "path"],
        "write_file" | "propose_write" => {
            &["deviceId", "rootId", "path", "content", "expectedHash"]
        }
        "operation_status" => &["deviceId", "operationId"],
        "terminal_execute" => &[
            "deviceId",
            "rootId",
            "requestId",
            "command",
            "cwd",
            "shell",
            "timeoutMs",
        ],
        "terminal_status" | "terminal_cancel" => &["deviceId", "rootId", "requestId"],
        _ => return Err(Error::new(501, "Unknown native tool.")),
    };
    value::fields(&call.args, keys)?;
    if let Value::Object(o) = call.args.value(call.args.root())? {
        for (k, id) in o.entries() {
            let key = String::from_utf16(k).map_err(|_| denied())?;
            match (key.as_str(), call.args.value(*id)?) {
                ("expectedHash", Value::Null) => {}
                ("timeoutMs", Value::Number(n))
                    if n.fract() == 0.0 && (100.0..=300000.0).contains(n) => {}
                ("timeoutMs", _) => return Err(Error::new(400, "Invalid terminal timeout.")),
                ("content" | "command", Value::String(units)) => {
                    let text = String::from_utf16_lossy(units);
                    if text.contains('\0')
                        || text.len() > if key == "command" { 16384 } else { 65536 }
                        || key == "command" && text.trim().is_empty()
                    {
                        return Err(Error::new(400, "Invalid tool text."));
                    }
                }
                (_, Value::String(units)) if units.len() <= 4096 => {}
                _ => return Err(Error::new(400, "Invalid tool argument.")),
            }
        }
    }
    let required: &[&str] = match call.tool.as_str() {
        "read_file" => &["rootId", "path"],
        "list_directory" => &["rootId"],
        "write_file" | "propose_write" => &["rootId", "path", "content", "expectedHash"],
        "operation_status" => &["operationId"],
        "terminal_execute" => &["rootId", "requestId", "command"],
        "terminal_status" | "terminal_cancel" => &["rootId", "requestId"],
        _ => &[],
    };
    if required
        .iter()
        .any(|k| value::prop(&call.args, k).is_none())
    {
        return Err(Error::new(400, "Missing tool argument."));
    }
    for key in ["operationId", "requestId"] {
        if let Some(id) = value::prop(&call.args, key) {
            let s = value::string(&call.args, Some(id)).ok_or_else(denied)?;
            if s.len() != 36
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
            {
                return Err(Error::new(400, "Invalid identifier."));
            }
        }
    }
    if let Some(id) = value::prop(&call.args, "expectedHash")
        && !matches!(call.args.value(id)?, Value::Null)
        && !value::string(&call.args, Some(id)).is_some_and(|s| hex(&s, 64))
    {
        return Err(Error::new(400, "Invalid expected hash."));
    }
    if let Some(id) = value::prop(&call.args, "shell")
        && !value::string(&call.args, Some(id))
            .is_some_and(|s| ["auto", "powershell", "bash", "sh"].contains(&s.as_str()))
    {
        return Err(Error::new(400, "Invalid shell."));
    }
    Ok(())
}
