//! Synchronous, instance-owned operation state. No filesystem, clock, or host imports.
use serde_json::{Value, json};
use std::collections::VecDeque;

pub const FRAME_BYTES: usize = 1024 * 1024;
const MAX_RECORDS: usize = 200;
type Result<T> = std::result::Result<T, &'static str>;

fn fields(v: &Value, required: &[&str], optional: &[&str]) -> Result<()> {
    let object = v.as_object().ok_or("EINPUT")?;
    if required.iter().any(|k| !object.contains_key(*k))
        || object
            .keys()
            .any(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
    {
        return Err("EINPUT");
    }
    Ok(())
}
fn string(v: &Value, limit: usize) -> Result<&str> {
    v.as_str()
        .filter(|s| s.encode_utf16().count() <= limit)
        .ok_or("EINPUT")
}
fn identifier(v: &Value) -> Result<&str> {
    let s = string(v, 36)?;
    if s.len() != 36
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || c == b'-')
    {
        return Err("EINPUT");
    }
    Ok(s)
}
fn hex(v: &Value, len: usize) -> Result<()> {
    let s = string(v, len)?;
    if s.len() != len
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("EINPUT");
    }
    Ok(())
}
fn root(v: &Value) -> Result<()> {
    let s = string(v, 80)?;
    if s.is_empty()
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err("EINPUT");
    }
    Ok(())
}
fn one_of(v: &Value, values: &[&str]) -> Result<()> {
    if !values.contains(&v.as_str().ok_or("EINPUT")?) {
        return Err("EINPUT");
    }
    Ok(())
}
fn owner(v: &Value) -> Result<()> {
    if v.is_null() {
        return Ok(());
    }
    fields(
        v,
        &[
            "version",
            "connectionId",
            "deviceId",
            "resource",
            "roots",
            "scopes",
        ],
        &[],
    )?;
    if v["version"] != 1 {
        return Err("EINPUT");
    }
    hex(&v["connectionId"], 32)?;
    hex(&v["deviceId"], 32)?;
    string(&v["resource"], 2048)?;
    let roots = v["roots"].as_array().ok_or("EINPUT")?;
    if roots.is_empty() || roots.len() > 50 {
        return Err("EINPUT");
    }
    for (index, share) in roots.iter().enumerate() {
        fields(share, &["rootId", "mode"], &[])?;
        root(&share["rootId"])?;
        one_of(&share["mode"], &["read-only", "review", "direct"])?;
        if roots[..index]
            .iter()
            .any(|item| item["rootId"] == share["rootId"])
        {
            return Err("EINPUT");
        }
    }
    let scopes = v["scopes"].as_array().ok_or("EINPUT")?;
    if scopes.len() > 4 || !scopes.contains(&json!("files:read")) {
        return Err("EINPUT");
    }
    for (index, scope) in scopes.iter().enumerate() {
        one_of(
            scope,
            &[
                "files:read",
                "files:write",
                "files:propose",
                "terminal:execute",
            ],
        )?;
        if scopes[..index].contains(scope) {
            return Err("EINPUT");
        }
    }
    Ok(())
}
fn registration(v: &Value) -> Result<()> {
    fields(
        v,
        &["operationId", "rootId", "path", "expectedHash", "content"],
        &["before"],
    )?;
    identifier(&v["operationId"])?;
    root(&v["rootId"])?;
    string(&v["path"], 4096)?;
    if !v["expectedHash"].is_null() {
        hex(&v["expectedHash"], 64)?;
    }
    for name in ["content", "before"] {
        if name == "before" && v.get(name).is_none() {
            continue;
        }
        let body = string(&v[name], 65536)?;
        if body.len() > 65536 || body.contains('\0') {
            return Err("EINPUT");
        }
    }
    Ok(())
}
fn outcome(v: &Value) -> Result<()> {
    fields(v, &["status"], &["message", "sha256", "backupSaved"])?;
    one_of(&v["status"], &["written", "approved", "failed", "unknown"])?;
    if let Some(message) = v.get("message") {
        string(message, 4096)?;
    }
    if let Some(hash) = v.get("sha256") {
        hex(hash, 64)?;
    }
    if let Some(saved) = v.get("backupSaved") {
        saved.as_bool().ok_or("EINPUT")?;
    }
    if ["written", "approved"].contains(&v["status"].as_str().unwrap_or("")) {
        hex(&v["sha256"], 64)?;
    }
    Ok(())
}
fn audit(action: &str, v: &Value) -> Result<()> {
    let keys: &[&str] = match action {
        "read" => &["rootId", "path"],
        "proposed" | "direct-write-requested" => &["operationId", "rootId", "path"],
        "rejected" => &["operationId"],
        "written" => &["operationId", "rootId", "path", "sha256", "authorization"],
        "directory-consent" => &["rootId", "from", "to", "flow"],
        "permission-changed" => &["rootId", "from", "to"],
        _ => return Err("EINPUT"),
    };
    fields(v, keys, &[])?;
    for key in keys {
        match *key {
            "operationId" => {
                identifier(&v[key])?;
            }
            "rootId" => root(&v[key])?,
            "path" => {
                string(&v[key], 4096)?;
            }
            "sha256" => hex(&v[key], 64)?,
            "authorization" => one_of(&v[key], &["local-review", "directory-direct"])?,
            "from" => one_of(
                &v[key],
                if action == "directory-consent" {
                    &["read-only", "review", "direct", "not-authorized"]
                } else {
                    &["read-only", "review", "direct"]
                },
            )?,
            "to" => one_of(
                &v[key],
                if action == "directory-consent" {
                    &["direct"]
                } else {
                    &["read-only", "review", "direct"]
                },
            )?,
            "flow" => one_of(&v[key], &["connection-guide"])?,
            _ => return Err("EINPUT"),
        }
    }
    Ok(())
}
fn projection(value: &Value, local: bool) -> Value {
    let public = [
        "operationId",
        "status",
        "path",
        "message",
        "sha256",
        "authorization",
        "backupSaved",
    ];
    let private = ["rootId", "expectedHash", "createdAt", "content", "before"];
    Value::Object(
        value
            .as_object()
            .unwrap()
            .iter()
            .filter(|(k, _)| {
                public.contains(&k.as_str()) || (local && private.contains(&k.as_str()))
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}
fn drop_body(record: &mut Value) {
    let object = record.as_object_mut().unwrap();
    object.remove("content");
    object.remove("before");
    object.remove("attempt");
}
fn ticket(record: &Value) -> Value {
    json!({ "attempt": record["attempt"], "operation": projection(record, true), "owner": record["owner"] })
}
fn unknown(id: &Value) -> Value {
    json!({ "operationId": id, "status": "unknown", "message": "Not retained for this connection or agent restarted. Do not assume a write succeeded." })
}

#[derive(Default)]
pub struct State {
    records: Vec<Value>,
    events: VecDeque<Value>,
    attempt: u64,
}
impl State {
    fn prune(&mut self, now: u64) {
        for record in &mut self.records {
            if record["status"] == "pending"
                && now.saturating_sub(record["createdAt"].as_u64().unwrap()) > 600000
            {
                record["status"] = json!("expired");
                drop_body(record);
            }
        }
        if self.records.len() >= 200 {
            let mut index = 0;
            while self.records.len() >= 100 && index < self.records.len() {
                if self.records[index]["status"] != "pending"
                    && self.records[index]["status"] != "applying"
                {
                    self.records.remove(index);
                } else {
                    index += 1;
                }
            }
        }
    }
    pub fn execute(&mut self, command: &Value) -> Result<Value> {
        let op = command["op"].as_str().ok_or("EINPUT")?;
        let keys: &[&str] = match op {
            "propose" | "beginDirect" => &["op", "input", "owner", "now"],
            "decide" => &["op", "id", "approved", "now"],
            "finish" => &["op", "id", "attempt", "outcome"],
            "prune" | "pendingIds" => &["op", "now"],
            "cancel" => &["op", "reason"],
            "status" => &["op", "id", "viewer", "now"],
            "snapshot" | "pendingView" => &["op", "id"],
            "snapshotIds" | "eventCount" => &["op"],
            "event" => &["op", "index"],
            "audit" => &["op", "action", "details", "at"],
            _ => return Err("EINPUT"),
        };
        fields(command, keys, &[])?;
        if let Some(now) = command.get("now") {
            let now = now
                .as_u64()
                .filter(|n| *n <= 9_007_199_254_740_991)
                .ok_or("EINPUT")?;
            self.prune(now);
        }
        if command.get("id").is_some() {
            identifier(&command["id"])?;
        }
        match op {
            "propose" | "beginDirect" => {
                let input = &command["input"];
                registration(input)?;
                owner(&command["owner"])?;
                if self
                    .records
                    .iter()
                    .any(|r| r["operationId"] == input["operationId"])
                {
                    return Err("EDUPLICATE");
                }
                if op == "propose"
                    && self
                        .records
                        .iter()
                        .filter(|r| r["status"] == "pending")
                        .count()
                        >= 20
                {
                    return Err("EPENDING");
                }
                if self.records.len() >= MAX_RECORDS {
                    return Err("ECAPACITY");
                }
                let mut record = input.clone();
                record["owner"] = command["owner"].clone();
                record["createdAt"] = command["now"].clone();
                record["status"] = json!(if op == "propose" {
                    "pending"
                } else {
                    "applying"
                });
                if op == "beginDirect" {
                    self.attempt = self.attempt.checked_add(1).ok_or("ECAPACITY")?;
                    record["attempt"] = json!(self.attempt.to_string());
                    record["authorization"] = json!("directory-direct");
                }
                let result = if op == "propose" {
                    projection(&record, false)
                } else {
                    ticket(&record)
                };
                self.records.push(record);
                Ok(result)
            }
            "decide" => {
                let approved = command["approved"].as_bool().ok_or("EINPUT")?;
                let record = self
                    .records
                    .iter_mut()
                    .find(|r| r["operationId"] == command["id"] && r["status"] == "pending")
                    .ok_or("ENOT_PENDING")?;
                if approved {
                    self.attempt = self.attempt.checked_add(1).ok_or("ECAPACITY")?;
                    record["status"] = json!("applying");
                    record["authorization"] = json!("local-review");
                    record["attempt"] = json!(self.attempt.to_string());
                    Ok(json!({ "ticket": ticket(record) }))
                } else {
                    record["status"] = json!("rejected");
                    drop_body(record);
                    Ok(json!({ "status": projection(record, false) }))
                }
            }
            "finish" => {
                outcome(&command["outcome"])?;
                string(&command["attempt"], 20)?;
                let record = self
                    .records
                    .iter_mut()
                    .find(|r| {
                        r["operationId"] == command["id"]
                            && r["status"] == "applying"
                            && r["attempt"] == command["attempt"]
                    })
                    .ok_or("EATTEMPT")?;
                let wanted = if record["authorization"] == "local-review" {
                    "approved"
                } else {
                    "written"
                };
                if [json!("written"), json!("approved")].contains(&command["outcome"]["status"])
                    && command["outcome"]["status"] != wanted
                {
                    return Err("EINPUT");
                }
                for (key, value) in command["outcome"].as_object().unwrap() {
                    record[key] = value.clone();
                }
                drop_body(record);
                Ok(projection(record, false))
            }
            "cancel" => {
                string(&command["reason"], 4096)?;
                for record in &mut self.records {
                    if record["status"] == "pending" {
                        record["status"] = json!("rejected");
                        record["message"] = command["reason"].clone();
                        drop_body(record);
                    }
                }
                Ok(Value::Null)
            }
            "status" => {
                let viewer = &command["viewer"];
                fields(
                    viewer,
                    &[
                        "local",
                        "connectionId",
                        "deviceId",
                        "resource",
                        "visibleRoots",
                    ],
                    &[],
                )?;
                let local = viewer["local"].as_bool().ok_or("EINPUT")?;
                if !viewer["connectionId"].is_null() {
                    hex(&viewer["connectionId"], 32)?;
                    hex(&viewer["deviceId"], 32)?;
                    string(&viewer["resource"], 2048)?;
                } else if !viewer["deviceId"].is_null() || !viewer["resource"].is_null() {
                    return Err("EINPUT");
                }
                let visible = viewer["visibleRoots"]
                    .as_array()
                    .filter(|r| r.len() <= 100)
                    .ok_or("EINPUT")?;
                for id in visible {
                    root(id)?;
                }
                let record = self
                    .records
                    .iter()
                    .find(|r| r["operationId"] == command["id"]);
                match record {
                    Some(record)
                        if local
                            || (record["owner"]["connectionId"] == viewer["connectionId"]
                                && record["owner"]["deviceId"] == viewer["deviceId"]
                                && record["owner"]["resource"] == viewer["resource"]
                                && (viewer["connectionId"].is_null()
                                    || visible.contains(&record["rootId"]))) =>
                    {
                        Ok(projection(record, false))
                    }
                    _ => Ok(unknown(&command["id"])),
                }
            }
            "pendingIds" => Ok(self
                .records
                .iter()
                .filter(|r| r["status"] == "pending")
                .map(|r| r["operationId"].clone())
                .collect()),
            "snapshotIds" => Ok(self
                .records
                .iter()
                .map(|r| r["operationId"].clone())
                .collect()),
            "snapshot" | "pendingView" => Ok(self
                .records
                .iter()
                .find(|r| {
                    r["operationId"] == command["id"]
                        && (op == "snapshot" || r["status"] == "pending")
                })
                .map(|r| projection(r, true))
                .unwrap_or(Value::Null)),
            "prune" => Ok(Value::Null),
            "eventCount" => Ok(json!(self.events.len())),
            "event" => {
                let index = command["index"]
                    .as_u64()
                    .filter(|n| *n < 100)
                    .ok_or("EINPUT")? as usize;
                Ok(self.events.get(index).cloned().unwrap_or(Value::Null))
            }
            "audit" => {
                let action = string(&command["action"], 32)?;
                audit(action, &command["details"])?;
                string(&command["at"], 32)?;
                let mut event = command["details"].clone();
                event["action"] = json!(action);
                event["at"] = command["at"].clone();
                self.events.push_back(event.clone());
                if self.events.len() > 100 {
                    self.events.pop_front();
                }
                Ok(event)
            }
            _ => Err("EINPUT"),
        }
    }
}

/// Invalid frames are ABI faults; command errors are bounded, nonfatal responses.
pub fn dispatch(state: &mut State, bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() > FRAME_BYTES {
        return None;
    }
    let request: Value = serde_json::from_slice(bytes).ok()?;
    fields(&request, &["v", "serial", "command"], &[]).ok()?;
    if request["v"] != 1
        || request["serial"]
            .as_u64()
            .filter(|n| *n <= 9_007_199_254_740_991)
            .is_none()
    {
        return None;
    }
    let response = match state.execute(&request["command"]) {
        Ok(result) => json!({ "v": 1, "serial": request["serial"], "ok": true, "result": result }),
        Err(code) => json!({ "v": 1, "serial": request["serial"], "ok": false, "error": code }),
    };
    let bytes = serde_json::to_vec(&response).ok()?;
    (bytes.len() <= FRAME_BYTES).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(n: usize) -> Value {
        json!({"operationId": format!("00000000-0000-0000-0000-{n:012x}"), "rootId": "project", "path": "note.txt", "expectedHash": null, "content": "new", "before": "old"})
    }
    fn add(state: &mut State, n: usize, op: &str) -> Result<Value> {
        state.execute(&json!({"op":op,"input":input(n),"owner":null,"now":0}))
    }
    #[test]
    fn atomic_pending_limit_and_detached_projection() {
        let mut state = State::default();
        for n in 0..20 {
            add(&mut state, n, "propose").unwrap();
        }
        assert_eq!(add(&mut state, 20, "propose"), Err("EPENDING"));
        let mut value = state
            .execute(&json!({"op":"snapshot","id":input(0)["operationId"]}))
            .unwrap();
        value["content"] = json!("changed");
        assert_eq!(state.records[0]["content"], "new");
    }
    #[test]
    fn approval_and_finish_are_once_and_attempt_bound() {
        let mut state = State::default();
        add(&mut state, 0, "propose").unwrap();
        let id = &input(0)["operationId"];
        assert_eq!(
            state.execute(&json!({"op":"decide","id":id,"approved":"yes","now":0})),
            Err("EINPUT")
        );
        let decision = state
            .execute(&json!({"op":"decide","id":id,"approved":true,"now":0}))
            .unwrap();
        assert_eq!(
            state.execute(&json!({"op":"decide","id":id,"approved":true,"now":0})),
            Err("ENOT_PENDING")
        );
        let mut finish =
            json!({"op":"finish","id":id,"attempt":"wrong","outcome":{"status":"failed"}});
        assert_eq!(state.execute(&finish), Err("EATTEMPT"));
        finish["attempt"] = decision["ticket"]["attempt"].clone();
        state.execute(&finish).unwrap();
        assert_eq!(state.execute(&finish), Err("EATTEMPT"));
        assert!(state.records[0].get("content").is_none());
    }
    #[test]
    fn expiry_is_strict_and_cancellation_does_not_cancel_applying() {
        let mut state = State::default();
        add(&mut state, 0, "propose").unwrap();
        add(&mut state, 1, "beginDirect").unwrap();
        state.prune(600000);
        assert_eq!(state.records[0]["status"], "pending");
        state.prune(600001);
        assert_eq!(state.records[0]["status"], "expired");
        state
            .execute(&json!({"op":"cancel","reason":"pause"}))
            .unwrap();
        assert_eq!(state.records[1]["status"], "applying");
    }
    #[test]
    fn prune_keeps_active_and_removes_old_terminal_until_99() {
        let mut state = State::default();
        add(&mut state, 0, "propose").unwrap();
        for n in 1..200 {
            let ticket = add(&mut state, n, "beginDirect").unwrap();
            state.execute(&json!({"op":"finish","id":input(n)["operationId"],"attempt":ticket["attempt"],"outcome":{"status":"failed"}})).unwrap();
        }
        state.prune(0);
        assert_eq!(state.records.len(), 99);
        assert_eq!(state.records[0]["status"], "pending");
        assert_eq!(state.records[1]["operationId"], input(102)["operationId"]);
    }
    #[test]
    fn frame_errors_are_fatal_but_commands_are_not() {
        let mut state = State::default();
        assert!(dispatch(&mut state, b"{}").is_none());
        let bytes = dispatch(
            &mut state,
            br#"{"v":1,"serial":1,"command":{"op":"bogus"}}"#,
        )
        .unwrap();
        let reply: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply["error"], "EINPUT");
    }
    #[test]
    fn events_are_content_free_bounded_and_individual() {
        let mut state = State::default();
        for n in 0..101 {
            state.execute(&json!({"op":"audit","action":"read","details":{"rootId":"r","path":format!("{n}")},"at":"now"})).unwrap();
        }
        assert_eq!(state.events.len(), 100);
        assert_eq!(state.events[0]["path"], "1");
        assert_eq!(state.execute(&json!({"op":"audit","action":"read","details":{"rootId":"r","path":"x","content":"secret"},"at":"now"})),Err("EINPUT"));
    }

    #[test]
    fn status_matches_full_owner_identity_not_just_connection() {
        let mut state = State::default();
        let owner = json!({"version":1,"connectionId":"a".repeat(32),"deviceId":"b".repeat(32),"resource":"https://relay.example/mcp","roots":[{"rootId":"project","mode":"direct"}],"scopes":["files:read","files:write"]});
        state
            .execute(&json!({"op":"propose","input":input(0),"owner":owner,"now":0}))
            .unwrap();
        let mut query = json!({"op":"status","id":input(0)["operationId"],"now":0,"viewer":{"local":false,"connectionId":owner["connectionId"],"deviceId":owner["deviceId"],"resource":owner["resource"],"visibleRoots":["project"]}});
        assert_eq!(state.execute(&query).unwrap()["status"], "pending");
        query["viewer"]["deviceId"] = json!("c".repeat(32));
        assert_eq!(state.execute(&query).unwrap()["status"], "unknown");
        query["viewer"]["deviceId"] = owner["deviceId"].clone();
        query["viewer"]["resource"] = json!("https://other.example/mcp");
        assert_eq!(state.execute(&query).unwrap()["status"], "unknown");
    }
}
