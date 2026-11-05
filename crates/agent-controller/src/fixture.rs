//! Owned local fixture controls. This module is absent from ordinary library builds.
use crate::{Error, Result, runtime::Host};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Condvar, Mutex, Weak},
    time::{Duration, Instant},
};
fn workflow_point(point: &str) -> bool {
    [
        "workflow:publish",
        "workflow:publish:vault",
        "workflow:publish:flow",
        "workflow:publish:intent",
        "workflow:publish:grant",
        "workflow:publish:confirmed",
        "workflow:publish:connected",
        "workflow:send",
        "workflow:browser-submitted",
        "workflow:activate",
        "workflow:response:enroll",
        "workflow:response:start",
        "workflow:response:prepare",
        "workflow:response:status",
        "workflow:response:confirm",
        "workflow:response:activate",
        "workflow:response:remove",
        "workflow:response:connections",
        "workflow:response:inspect",
        "workflow:response:handoff",
    ]
    .contains(&point)
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub addresses: BTreeMap<String, std::net::SocketAddr>,
    pub ca: Option<String>,
    pub system: Option<String>,
    #[serde(rename = "systemQuery")]
    pub system_query: Option<crate::network_query::Mode>,
}
struct Hold {
    deadline: Instant,
    entered: u64,
}
#[derive(Default)]
struct State {
    request_disconnects: u64,
    armed: BTreeMap<String, String>,
    holds: BTreeMap<String, Hold>,
    entered: BTreeMap<String, u64>,
    observations: Vec<Value>,
}
#[derive(Default)]
pub struct Hooks {
    state: Mutex<State>,
    wake: Condvar,
    async_wake: tokio::sync::Notify,
}
impl Hooks {
    pub(crate) fn request_disconnected(&self) {
        self.state.lock().unwrap().request_disconnects += 1;
    }
    pub(crate) fn elapsed(&self, point: &str, start: Instant) {
        let mut state = self.state.lock().unwrap();
        if state.observations.len() < 128 {
            state
                .observations
                .push(json!({"point":point,"elapsedMs":start.elapsed().as_millis()}));
        }
    }
    pub(crate) fn check(&self, point: &str) -> Result<()> {
        let kind = self.state.lock().unwrap().armed.remove(point);
        match kind.as_deref() {
            Some("panic") => panic!("Owned fixture injected failure at {point}"),
            Some("error") => Err(Error::new(503, "Owned fixture injected failure.")),
            _ => Ok(()),
        }
    }
    pub(crate) fn wait(&self, point: &str) {
        let mut state = self.state.lock().unwrap();
        if !state.holds.contains_key(point) {
            return;
        }
        *state.entered.entry(point.to_owned()).or_default() += 1;
        if let Some(hold) = state.holds.get_mut(point) {
            hold.entered += 1;
        }
        while let Some(hold) = state.holds.get(point) {
            let remaining = hold.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.holds.remove(point);
                break;
            }
            state = self.wake.wait_timeout(state, remaining).unwrap().0;
        }
    }
    pub(crate) async fn wait_async(&self, point: &str) {
        let mut entered = false;
        loop {
            let wake = self.async_wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let remaining = {
                let mut state = self.state.lock().unwrap();
                let Some(hold) = state.holds.get(point) else {
                    return;
                };
                let remaining = hold.deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    state.holds.remove(point);
                    return;
                }
                if !entered {
                    *state.entered.entry(point.to_owned()).or_default() += 1;
                    entered = true;
                }
                remaining
            };
            tokio::select! {_=wake=>{},_=tokio::time::sleep(remaining)=>{}}
        }
    }
    fn control(&self, value: &Value) -> Result<Value> {
        let point = value["point"].as_str().unwrap_or("");
        let mut state = self.state.lock().unwrap();
        match value["op"].as_str() {
            Some("arm")
                if ([
                    "core:admit",
                    "core:finish",
                    "core:snapshot",
                    "core:bridgeEvent",
                    "core:replyPermit",
                    "effect",
                    "save",
                    "read",
                    "progress",
                    "business",
                    "write:ready",
                    "operation:finish",
                    "journal",
                    "journal:reserve",
                    "journal:reserved",
                    "journal:save",
                ]
                .contains(&point)
                    || workflow_point(point))
                    && ["error", "panic"].contains(&value["kind"].as_str().unwrap_or("")) =>
            {
                state
                    .armed
                    .insert(point.to_owned(), value["kind"].as_str().unwrap().to_owned());
            }
            Some("hold")
                if [
                    "consent:checked",
                    "consent:publish",
                    "platform:register",
                    "platform:pause",
                    "platform:spawn",
                    "platform:commit",
                    "platform:drain",
                    "platform:browse",
                    "network:drain",
                    "save",
                    "read",
                    "reply",
                    "write:ready",
                    "write:committed",
                    "journal",
                    "journal:reserve",
                    "journal:reserved",
                    "journal:save",
                    "terminal:ready",
                    "terminal:spawn",
                ]
                .contains(&point)
                    || workflow_point(point) =>
            {
                let ms = value["timeoutMs"].as_u64().unwrap_or(30000);
                if ms == 0 || ms > 120000 {
                    return Err(Error::new(400, "Bounded hold required."));
                }
                state.holds.insert(
                    point.to_owned(),
                    Hold {
                        deadline: Instant::now() + Duration::from_millis(ms),
                        entered: 0,
                    },
                );
            }
            Some("release")
                if [
                    "consent:checked",
                    "consent:publish",
                    "platform:register",
                    "platform:pause",
                    "platform:spawn",
                    "platform:commit",
                    "platform:drain",
                    "platform:browse",
                    "network:drain",
                    "save",
                    "read",
                    "reply",
                    "write:ready",
                    "write:committed",
                    "journal",
                    "journal:reserve",
                    "journal:reserved",
                    "journal:save",
                    "terminal:ready",
                    "terminal:spawn",
                ]
                .contains(&point)
                    || workflow_point(point) =>
            {
                state.holds.remove(point);
                self.wake.notify_all();
                self.async_wake.notify_waiters();
            }
            Some("inspect") => {}
            _ => return Err(Error::new(400, "Invalid fixture control.")),
        }
        Ok(
            json!({"held":state.holds.keys().collect::<Vec<_>>(),"entered":state.entered,"observations":state.observations,"requestDisconnects":state.request_disconnects}),
        )
    }
}
#[derive(Clone)]
pub struct Control {
    pub(crate) host: Weak<Host>,
    pub(crate) hooks: Arc<Hooks>,
}
impl Control {
    pub async fn platform(&self, value: &Value) -> Result<Value> {
        let host = self
            .host
            .upgrade()
            .ok_or_else(|| Error::new(503, "Fixture closed."))?;
        if !host.platform.fixture_browser_allowed() {
            return Err(Error::new(
                400,
                "Explicit synthetic browser fixture required.",
            ));
        }
        host.platform.browser(&host, &value["target"]).await
    }
    pub async fn network(&self, value: &Value) -> Result<Value> {
        let host = self
            .host
            .upgrade()
            .ok_or_else(|| Error::new(503, "Fixture closed."))?;
        let origin = value["origin"]
            .as_str()
            .ok_or_else(|| Error::new(400, "Origin required."))?;
        if value["op"] == "network-system-query" {
            return host.network.system_query(&host, origin).await;
        }
        let force = value["force"].as_bool().unwrap_or(false);
        let p = host.network.prepare(&host, origin, force).await?;
        Ok(json!({"revision":p.revision,"network":host.network.status()}))
    }
    pub fn execute(&self, value: &Value) -> Result<Value> {
        let host = self
            .host
            .upgrade()
            .ok_or_else(|| Error::new(503, "Fixture closed."))?;
        if value["op"] == "platform-config" {
            let mut input = value.clone();
            input.as_object_mut().unwrap().remove("op");
            input.as_object_mut().unwrap().remove("id");
            return host.platform.configure(&input);
        }
        if value["op"] == "platform-inspect" {
            return Ok(host.platform.inspect());
        }
        if value["op"] == "network-query" {
            let mode = serde_json::from_value(value["query"].clone())
                .map_err(|_| Error::new(400, "Invalid query fixture."))?;
            host.network.query_mode(mode)?;
            return Ok(json!({"configured":true}));
        }
        if value["op"] == "terminal-stall" {
            let ms = value["timeoutMs"]
                .as_u64()
                .filter(|ms| (1..=10000).contains(ms))
                .ok_or_else(|| Error::new(400, "Bounded terminal stall required."))?;
            host.terminal
                .stall_ms
                .store(ms as usize, std::sync::atomic::Ordering::SeqCst);
            return Ok(json!({"armed":true}));
        }
        if value["op"] == "trigger" && value["point"] == "close" {
            host.close();
            return Ok(json!({"triggered":true,"closing":true}));
        }
        if value["op"] == "trigger" && value["point"] == "snapshot" {
            let result = host.command(json!({"op":"snapshot"}));
            return Ok(json!({"triggered":true,"refused":result.is_err(),"fault":host.faulted()}));
        }
        let mut result = self.hooks.control(value)?;
        for (key, value) in host.platform.inspect().as_object().unwrap() {
            result[key] = value.clone();
        }
        result["fault"] = json!(host.faulted());
        result["workflowActive"] = json!(host.workflows.active());
        result["setupActive"] = json!(host.workflows.setup_active());
        result["networkRevision"] = json!(host.network.revision());
        result["networkPending"] = json!(host.network.pending());
        result["queryStarts"] = json!(
            host.network
                .query
                .starts
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        result["queryActive"] = json!(
            host.network
                .query
                .active
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        result["queryPids"] = json!(*host.network.query.pids.lock().unwrap());
        result["closing"] = json!(host.closing.load(std::sync::atomic::Ordering::SeqCst));
        result["pendingPersistence"] = json!(host.persistence.pending());
        result["pendingTerminalPersistence"] = json!(host.terminal.journal.pending());
        result["terminalJobsRunning"] = json!(host.terminal.active());
        result["terminalSupervisors"] = json!(host.terminal.supervisors());
        result["pendingControlIo"] = json!(
            host.terminal
                .control_pending
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        result["observedPendingControlIo"] = json!(
            host.terminal
                .observed_pending
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        Ok(result)
    }
}
