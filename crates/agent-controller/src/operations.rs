//! Native operation authority and guarded write composition. History is intentionally volatile.
use crate::{
    Error, Result,
    bridge::Socket,
    persistence::confirmed,
    runtime::{Host, State},
    tools::{self, Call},
    value,
};
use chat2local_protocol::{Request, WriteAuthorization, WriteRequest};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::Ordering};
fn error(code: &str) -> Error {
    Error::new(400, format!("File operation refused ({code})."))
}
fn now() -> u64 {
    crate::management::now() as u64
}
pub fn cancel_pending(state: &mut State) {
    // Restrictive recovery must remain usable even if volatile file history failed.
    if state.operations_healthy {
        let _ = core(state, json!({"op":"cancel","reason":"Permission changed."}));
    }
}
fn core(state: &mut State, command: Value) -> Result<Value> {
    if !state.operations_healthy {
        return Err(Error::new(
            503,
            "File history unavailable; new writes are frozen.",
        ));
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.audit.execute(&command)
    }));
    match result {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(code)) => {
            if !["EPENDING", "ECAPACITY", "ENOT_PENDING", "EEXISTS"].contains(&code) {
                state.operations_healthy = false;
            }
            Err(error(code))
        }
        Err(_) => {
            state.operations_healthy = false;
            Err(Error::new(503, "File operation state failed."))
        }
    }
}
pub fn projection(state: &mut State) -> Result<(Value, Value)> {
    if !state.operations_healthy {
        return Ok((json!([]), json!([])));
    }
    let ids = core(state, json!({"op":"pendingIds","now":now()}))?;
    let mut pending = Vec::new();
    for id in ids.as_array().into_iter().flatten() {
        let mut row = core(state, json!({"op":"pendingView","id":id}))?;
        if row.is_null() {
            continue;
        }
        let label = value::array(&state.config, value::prop(&state.config, "roots"))
            .unwrap_or_default()
            .into_iter()
            .find(|r| {
                value::string(&state.config, value::get(&state.config, *r, "id")).as_deref()
                    == row["rootId"].as_str()
            })
            .and_then(|r| value::string(&state.config, value::get(&state.config, r, "label")))
            .unwrap_or_default();
        row["rootLabel"] = json!(label);
        pending.push(row);
    }
    let count = core(state, json!({"op":"eventCount"}))?
        .as_u64()
        .unwrap_or(0);
    let mut events = Vec::new();
    for index in 0..count {
        events.push(core(state, json!({"op":"event","index":index}))?);
    }
    Ok((json!(pending), json!(events)))
}
pub(crate) async fn audit(host: &Host, action: &str, details: Value) -> Result<()> {
    let event = core(
        &mut host.lock_state(),
        json!({"op":"audit","action":action,"details":details,"at":tools::iso_now()}),
    )?;
    let doc = value::parse(event.to_string().as_bytes())?;
    let receive = host.persistence.submit(move |store| {
        store.append_audit(&doc)?;
        Ok(())
    })?;
    confirmed(receive, false).await
}
fn owner(call: &Call) -> Result<Value> {
    call.access
        .as_ref()
        .map(|d| {
            value::serialized(d)
                .and_then(|s| serde_json::from_str(&s).map_err(|_| error("EACCESS")))
        })
        .transpose()
        .map(|v| v.unwrap_or(Value::Null))
}
fn status(state: &mut State, call: &Call) -> Result<Value> {
    let id = value::string(&call.args, value::prop(&call.args, "operationId")).unwrap_or_default();
    let unknown = json!({"operationId":id,"status":"unknown","message":"Not retained for this connection or agent restarted. Do not assume a write succeeded."});
    if !state.operations_healthy
        || value::boolean(&state.config, value::prop(&state.config, "paused")) != Some(false)
    {
        return Ok(unknown);
    }
    let identity = tools::identity(&state.secrets)?;
    let access = tools::access(call, &identity)?;
    let visible = value::array(&state.config, value::prop(&state.config, "roots"))
        .unwrap_or_default()
        .into_iter()
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
                }),
        )
        .filter_map(|r| {
            let id = value::string(&state.config, value::get(&state.config, r, "id"))?;
            tools::effective(
                &crate::root_mode(&state.config, r).ok()?,
                access.as_ref(),
                &id,
            )
            .map(|_| id)
        })
        .collect::<Vec<_>>();
    core(
        state,
        json!({"op":"status","id":id,"now":now(),"viewer":{"local":false,"connectionId":access.as_ref().map(|a|&a.connection_id),"deviceId":access.as_ref().map(|a|&a.device_id),"resource":access.as_ref().map(|a|&a.resource),"visibleRoots":visible}}),
    )
}
pub async fn execute(
    host: &Arc<Host>,
    call: &Call,
    socket: &Arc<Socket>,
    fingerprint: &str,
    request: Option<Request>,
) -> Result<String> {
    if call.tool == "operation_status" {
        return status(&mut host.lock_state(), call).map(|v| v.to_string());
    }
    let request = request.ok_or_else(|| error("EINPUT"))?;
    let id = crate::uuid()?;
    let mut input = json!({"operationId":id,"rootId":request.args.root_id,"path":request.args.path,"content":value::execution_string(&call.args,value::prop(&call.args,"content")).ok_or_else(||error("EINPUT"))?,"expectedHash":value::string(&call.args,value::prop(&call.args,"expectedHash"))});
    if call.tool == "propose_write" {
        let owner = host.clone();
        let captured = call.copy()?;
        let socket = socket.clone();
        let expected = fingerprint.to_owned();
        let snapshot = tokio::task::spawn_blocking(move || {
            let _root = chat2local_agent_platform::GuardedDirectory::root(
                &request.authority.root.path,
                &owner.store.directory().to_string_lossy(),
            )
            .map_err(|e| error(e.code))?;
            socket.with_current(&owner, &captured, &expected, |_| Ok(()))?;
            chat2local_agent_platform::snapshot(&request, true).map_err(|e| error(e.code))
        })
        .await
        .map_err(|_| error("EWORKER"))??;
        if input["expectedHash"] != snapshot["sha256"] {
            return Err(error("ECONFLICT"));
        }
        input["before"] = snapshot["content"].clone();
    }
    let ticket=socket.with_current(host,call,fingerprint,|state|core(state,json!({"op":if call.tool=="propose_write"{"propose"}else{"beginDirect"},"input":input,"owner":owner(call)?,"now":now()})))?;
    let audited = audit(
        host,
        if call.tool == "propose_write" {
            "proposed"
        } else {
            "direct-write-requested"
        },
        json!({"operationId":id,"rootId":input["rootId"],"path":input["path"]}),
    )
    .await;
    if let Err(e) = audited {
        if call.tool == "write_file" {
            return finish(
                host,
                &ticket,
                json!({"status":"failed","message":e.message}),
            )
            .map(|v| v.to_string());
        }
        return Err(e);
    }
    if call.tool == "propose_write" {
        return Ok(ticket.to_string());
    }
    commit(
        host,
        ticket,
        Some((call.copy()?, socket.clone(), fingerprint.to_owned())),
    )
    .await
    .map(|v| v.to_string())
}
fn ticket_call(ticket: &Value) -> Result<Call> {
    let op = &ticket["operation"];
    Ok(Call{diagnostics:None,id:crate::uuid()?,tool:if op["authorization"]=="directory-direct"{"write_file"}else{"propose_write"}.into(),args:value::parse(json!({"rootId":op["rootId"],"path":op["path"],"content":op["content"],"expectedHash":op["expectedHash"]}).to_string().as_bytes())?,access:if ticket["owner"].is_null(){None}else{Some(value::parse(ticket["owner"].to_string().as_bytes())?)}})
}
fn authorized(host: &Host, call: &Call) -> Result<Request> {
    if host.faulted() || host.closing.load(Ordering::SeqCst) {
        return Err(error("EACCESS"));
    }
    let state = host.lock_state();
    if !state.operations_healthy {
        return Err(error("ECORE"));
    }
    tools::prepare(&state, call)?
        .request
        .ok_or_else(|| error("EINPUT"))
}
async fn commit(
    host: &Arc<Host>,
    ticket: Value,
    remote: Option<(Call, Arc<Socket>, String)>,
) -> Result<Value> {
    let call = ticket_call(&ticket)?;
    let id = ticket["operation"]["operationId"]
        .as_str()
        .ok_or_else(|| error("EINPUT"))?
        .to_owned();
    let request = match authorized(host, &call) {
        Ok(request) => request,
        Err(e) => {
            return finish(
                host,
                &ticket,
                json!({"status":"failed","message":e.message}),
            );
        }
    };
    let write = WriteRequest {
        request,
        operation_id: id.clone(),
        authorization: if ticket["operation"]["authorization"] == "local-review" {
            WriteAuthorization::LocalReview
        } else {
            WriteAuthorization::DirectoryDirect
        },
        expected_hash: ticket["operation"]["expectedHash"]
            .as_str()
            .map(str::to_owned),
        content: ticket["operation"]["content"]
            .as_str()
            .ok_or_else(|| error("EINPUT"))?
            .into(),
        state_dir: host.store.directory().to_string_lossy().into_owned(),
    };
    let success = if write.authorization == WriteAuthorization::LocalReview {
        "approved"
    } else {
        "written"
    };
    let owner = host.clone();
    let intent = crate::random(32)?;
    let outcome=tokio::task::spawn_blocking(move||->Result<Value>{
  let store=owner.store.clone();let guard:chat2local_agent_platform::PublicationGuard=Arc::new(move||store.check_owner().map_err(|_|chat2local_protocol::Failure::new("EOWNER","Controller ownership changed.")));
  let _root=chat2local_agent_platform::GuardedDirectory::root(&write.request.authority.root.path,&write.state_dir).map_err(|e|error(e.code))?;
  let gate=chat2local_agent_platform::WriteGate::acquire(&write.state_dir,guard.clone()).map_err(|e|error(e.code))?;
  chat2local_native_store::check_fence(owner.store.directory(),true)?;
  let actual=(||{let mut prepared=chat2local_agent_platform::PreparedWrite::prepare_guarded(&write,&intent,guard.clone()).map_err(|e|e.code)?;
   #[cfg(feature="fixture")] {owner.hooks.wait("write:ready");owner.hooks.check("write:ready").map_err(|_|"EINJECTED")?;}
   owner.store.check_owner().map_err(|_|"EOWNER")?;
   if let Some((captured,socket,expected))=&remote {socket.with_current(&owner,captured,expected,|state|if state.operations_healthy{Ok(())}else{Err(error("ECORE"))}).map_err(|_|"EACCESS")?;}else{authorized(&owner,&call).map_err(|_|"EACCESS")?;}
   let result=prepared.commit_admitted(|submit|{
     let result=if let Some((captured,socket,expected))=&remote {socket.with_current(&owner,captured,expected,|state|{if !state.operations_healthy{return Err(error("ECORE"));}submit().map_err(|e|error(e.code))})}else{
       let _core=owner.core.lock().unwrap_or_else(|e|e.into_inner());let state=owner.lock_state();if owner.faulted()||owner.closing.load(Ordering::SeqCst)||!state.operations_healthy||tools::prepare(&state,&call).is_err(){Err(error("EACCESS"))}else{submit().map_err(|e|error(e.code))}
     };result.map_err(|_|chat2local_protocol::Failure::new("EACCESS","Commit admission refused."))
   });drop(prepared);result.map_err(|e|e.code)
  })();
  let unknown=actual.as_ref().is_err_and(|code|*code=="EUNKNOWN");
  let released=if unknown{false}else{chat2local_native_store::check_fence(owner.store.directory(),true).is_ok()&&gate.release().is_ok()};
  let mut outcome=match actual{Ok(v)=>json!({"status":success,"sha256":v["sha256"],"backupSaved":v["backupSaved"]}),Err(code)=>json!({"status":if unknown{"unknown"}else{"failed"},"message":format!("Native write completion: {code}. Do not retry blindly.")})};
  if !released && !unknown {outcome["message"]=json!("Write gate remains retained; further writes are fenced.");}
  #[cfg(feature="fixture")]owner.hooks.wait("write:committed");
  Ok(outcome)
 }).await.unwrap_or_else(|_|{host.lock_state().operations_healthy=false;Ok(json!({"status":"unknown","message":"Write worker failed; actual completion is unknown. Do not retry blindly."}))}).unwrap_or_else(|e|json!({"status":"failed","message":e.message}));
    let result = finish(host, &ticket, outcome)?;
    if ["written","approved"].contains(&result["status"].as_str().unwrap_or("")) && audit(host,"written",json!({"operationId":id,"rootId":ticket["operation"]["rootId"],"path":ticket["operation"]["path"],"sha256":result["sha256"],"authorization":ticket["operation"]["authorization"]})).await.is_err(){let mut result=result;result["message"]=json!("Write completed, but audit/history persistence failed. Read back before retrying.");return Ok(result);}
    Ok(result)
}
fn finish(host: &Host, ticket: &Value, outcome: Value) -> Result<Value> {
    let result = {
        let mut state = host.lock_state();
        let completion = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[cfg(feature = "fixture")]
            host.hooks.check("operation:finish")?;
            core(
                &mut state,
                json!({"op":"finish","id":ticket["operation"]["operationId"],"attempt":ticket["attempt"],"outcome":outcome}),
            )
        })).unwrap_or_else(|_|Err(error("ECORE")));
        match completion {
            Ok(v) => v,
            Err(_) => {
                state.operations_healthy = false;
                let mut v = json!({});
                if let Some(o) = v.as_object_mut() {
                    for key in [
                        "operationId",
                        "status",
                        "path",
                        "message",
                        "sha256",
                        "authorization",
                        "backupSaved",
                    ] {
                        if let Some(value) = ticket["operation"].get(key) {
                            o.insert(key.into(), value.clone());
                        }
                    }
                    for (k, val) in outcome.as_object().unwrap() {
                        o.insert(k.clone(), val.clone());
                    }
                    o.insert("message".into(),json!("Actual write receipt retained, but history failed; new writes are frozen. Read back before any retry."));
                }
                v
            }
        }
    };
    Ok(result)
}
pub async fn approve(
    host: &Arc<Host>,
    input: &chat2local_js_value_compat::Document,
) -> Result<Value> {
    value::fields(input, &["operationId", "approved"])?;
    let id = value::string(input, value::prop(input, "operationId"))
        .filter(|s| {
            s.len() == 36
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
        })
        .ok_or_else(|| error("EINPUT"))?;
    let approved =
        value::boolean(input, value::prop(input, "approved")).ok_or_else(|| error("EINPUT"))?;
    let result = core(
        &mut host.lock_state(),
        json!({"op":"decide","id":id,"approved":approved,"now":now()}),
    )?;
    if !approved {
        audit(host, "rejected", json!({"operationId":id})).await?;
        Ok(result["status"].clone())
    } else {
        commit(host, result["ticket"].clone(), None).await
    }
}
