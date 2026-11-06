use crate::{
    Error, Options, Ready, Reply, Request, Result, bridge, controller, management,
    persistence::Persistence, value,
};
use chat2local_agent_lifecycle_core::State as Lifecycle;
use chat2local_js_value_compat::{Document, Value};
use chat2local_native_store::Store;
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::{Notify, Semaphore, mpsc, oneshot, watch};

pub(crate) struct State {
    pub config: Document,
    pub secrets: Document,
    pub epoch: u64,
    pub last_remote: Option<String>,
    pub bridge_warning: Option<String>,
    pub guide_warning: Option<String>,
    pub guide_session: Option<(f64, serde_json::Value)>,
    pub guide_remote: Option<(f64, serde_json::Value)>,
    pub persistence_warning: Option<String>,
    pub terminal_available: bool,
    pub operations_healthy: bool,
    pub audit: chat2local_operation_core::State,
}
pub(crate) enum Job {
    Workflow {
        ticket: String,
        work: crate::workflow::Commit,
        reply: oneshot::Sender<Result<crate::workflow_value::Doc>>,
    },
    Http {
        ticket: String,
        request: Request,
        reply: oneshot::Sender<Reply>,
    },
    Remote {
        ticket: String,
        call: bridge::Call,
        socket: Arc<bridge::Socket>,
    },
}
impl Job {
    fn ticket(&self) -> &str {
        match self {
            Self::Http { ticket, .. }
            | Self::Remote { ticket, .. }
            | Self::Workflow { ticket, .. } => ticket,
        }
    }
}
pub(crate) struct Host {
    pub core: Mutex<Lifecycle>,
    pub state: Mutex<State>,
    pub store: Arc<Store>,
    pub persistence: Arc<Persistence>,
    pub terminal: Arc<crate::terminal::Service>,
    pub network: Arc<crate::network::Service>,
    pub platform: Arc<crate::platform::Service>,
    pub workflows: Arc<crate::workflow::Service>,
    pub sessions: Mutex<management::Sessions>,
    pub origin: String,
    pub token: String,
    pub instance: String,
    pub active: AtomicBool,
    pub closing: AtomicBool,
    fault: AtomicBool,
    fault_applied: AtomicBool,
    pub authentication: Arc<Semaphore>,
    jobs: mpsc::Sender<Job>,
    pub effects: mpsc::Sender<serde_json::Value>,
    pub bridge_stop: watch::Sender<bool>,
    pub admission: Arc<crate::http::Admission>,
    pending: AtomicUsize,
    drained: Notify,
    recovery: Semaphore,
    #[cfg(feature = "fixture")]
    pub hooks: Arc<crate::fixture::Hooks>,
}
impl Host {
    /// Fault recovery may acquire a poisoned guard before the worker applies its
    /// pause overlay. Every ordinary authority gate still checks the fault latch.
    pub fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn faulted(&self) -> bool {
        self.fault.load(Ordering::SeqCst)
    }
    pub fn latch_while_locked(&self, _core: &mut Lifecycle) {
        self.fault.store(true, Ordering::SeqCst);
    }
    pub fn poison(&self) {
        {
            let _core = self.core.lock().unwrap_or_else(|e| e.into_inner());
            self.fault.store(true, Ordering::SeqCst);
        }
        if self.fault_applied.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.state.clear_poison();
        state.epoch += 1;
        let _ = value::put(&mut state.config, "paused", Value::Bool(true));
        state.persistence_warning = Some("Fault pause is in memory; durable restriction requires authenticated local confirmation.".into());
        drop(state);
        self.terminal.stop_all();
        self.workflows.close();
        self.network.close();
        self.platform.close();
        self.bridge_stop.send_replace(true);
    }
    pub fn execute_locked(
        &self,
        core: &mut Lifecycle,
        command: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let result = (|| {
            if self.faulted() {
                return Err(Error::new(503, "Lifecycle permanently failed."));
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #[cfg(feature = "fixture")]
                self.hooks
                    .check(&format!("core:{}", command["op"].as_str().unwrap_or("")))?;
                core.execute(command)
                    .map_err(|e| Error::new(if e == "EBUSY" { 429 } else { 503 }, e))
            }))
            .unwrap_or_else(|_| Err(Error::new(503, "Lifecycle panicked.")))?;
            let effects = result["effects"]
                .as_array()
                .ok_or_else(|| Error::new(503, "Invalid lifecycle effects."))?;
            for effect in effects {
                let kind = effect["type"]
                    .as_str()
                    .ok_or_else(|| Error::new(503, "Invalid lifecycle effect."))?;
                if ![
                    "runTicket",
                    "drained",
                    "cancelSetup",
                    "cancelPicker",
                    "clearBridge",
                    "armTimer",
                    "retireAttempt",
                    "cancelTimers",
                    "prepareNetwork",
                    "openSocket",
                    "publishMetadata",
                    "sendPing",
                ]
                .contains(&kind)
                {
                    return Err(Error::new(503, "Unknown lifecycle effect."));
                }
                if kind == "cancelPicker" {
                    self.platform.cancel_picker();
                }
                if kind == "cancelSetup" {
                    self.workflows.cancel();
                }
                if !["runTicket", "drained", "cancelSetup", "cancelPicker"].contains(&kind) {
                    self.effects
                        .try_send(effect.clone())
                        .map_err(|_| Error::new(503, "Lifecycle effect capacity unavailable."))?;
                }
            }
            Ok(result)
        })();
        if result.as_ref().is_err_and(|e| e.status != 429) {
            self.fault.store(true, Ordering::SeqCst);
        }
        result
    }
    pub fn command(&self, command: serde_json::Value) -> Result<serde_json::Value> {
        let result = {
            let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
            let result = self.execute_locked(&mut core, &command);
            if result.as_ref().is_err_and(|e| e.status != 429) {
                self.fault.store(true, Ordering::SeqCst);
            }
            result
        };
        if result.as_ref().is_err_and(|e| e.status != 429) {
            self.poison();
        }
        result
    }
    fn enqueue(&self, build: impl FnOnce(String) -> Job) -> Result<()> {
        let result = (|| {
            let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
            if !self.active.load(Ordering::SeqCst)
                || self.closing.load(Ordering::SeqCst)
                || self.faulted()
            {
                return Err(Error::new(429, "Ordinary admission is closed."));
            }
            let v = match self.execute_locked(&mut core, &json!({"op":"admit","capacity":24})) {
                Ok(v) => v,
                Err(e) => {
                    if e.status != 429 {
                        self.fault.store(true, Ordering::SeqCst);
                    }
                    return Err(e);
                }
            };
            let ticket = v["result"]["ticket"]
                .as_str()
                .ok_or_else(|| {
                    self.fault.store(true, Ordering::SeqCst);
                    Error::new(503, "Invalid FIFO receipt.")
                })?
                .to_owned();
            self.pending.fetch_add(1, Ordering::SeqCst);
            if self.jobs.try_send(build(ticket)).is_err() {
                self.pending.fetch_sub(1, Ordering::SeqCst);
                self.fault.store(true, Ordering::SeqCst);
                return Err(Error::new(503, "FIFO resource unavailable."));
            }
            Ok(())
        })();
        if result.as_ref().is_err_and(|e| e.status != 429) {
            self.poison();
        }
        result
    }
    pub async fn dispatch(self: &Arc<Self>, request: Request) -> Reply {
        if !self.active.load(Ordering::SeqCst) {
            return Reply::error(Error::new(503, "Controller is closing."));
        }
        if self.faulted() {
            let Ok(_slot) = self.recovery.try_acquire() else {
                return Reply::error(Error::new(429, "Recovery capacity reached."));
            };
            return controller::execute(self, request, true)
                .await
                .unwrap_or_else(Reply::error);
        }
        if crate::workflow::route(&request.target)
            || [
                "/api/pick-folder",
                "/api/folder/select",
                "/api/folder/browse",
                "/api/folder/cancel",
            ]
            .contains(&request.target.as_str())
        {
            return controller::execute(self, request, false)
                .await
                .unwrap_or_else(Reply::error);
        }
        let (reply, receive) = oneshot::channel();
        if let Err(e) = self.enqueue(|ticket| Job::Http {
            ticket,
            request,
            reply,
        }) {
            return Reply::error(e);
        }
        receive
            .await
            .unwrap_or_else(|_| Reply::error(Error::new(503, "Controller worker unavailable.")))
    }
    pub fn remote(&self, call: bridge::Call, socket: Arc<bridge::Socket>) -> Result<()> {
        self.enqueue(|ticket| Job::Remote {
            ticket,
            call,
            socket,
        })
    }
    pub fn enqueue_workflow(
        &self,
        work: crate::workflow::Commit,
        reply: oneshot::Sender<Result<crate::workflow_value::Doc>>,
    ) -> Result<()> {
        self.enqueue(|ticket| Job::Workflow {
            ticket,
            work,
            reply,
        })
    }
    pub fn close(&self) {
        let failure = {
            let mut core = self.core.lock().unwrap_or_else(|e| e.into_inner());
            self.active.store(false, Ordering::SeqCst);
            if self.closing.swap(true, Ordering::SeqCst) {
                return;
            }
            !self.faulted()
                && self
                    .execute_locked(&mut core, &json!({"op":"beginClose"}))
                    .is_err()
        };
        if failure {
            self.poison();
        }
        self.terminal.stop_all();
        self.workflows.close();
        self.network.close();
        self.platform.close();
        self.bridge_stop.send_replace(true);
        // One accept waiter: retain the permit when closing precedes registration.
        self.admission.close();
    }
    pub fn pending(&self) -> usize {
        self.pending.load(Ordering::SeqCst)
    }
    async fn drain(&self) {
        while self.pending() != 0 {
            self.drained.notified().await;
        }
    }
}
pub async fn run(options: Options, on_ready: impl FnOnce(Ready)) -> Result<()> {
    if options.port == 0
        || cfg!(feature = "fixture") && options.port == 47631
        || !options.directory.is_absolute()
    {
        return Err(Error::new(
            400,
            "Explicit absolute synthetic directory and selected non-production port required.",
        ));
    }
    let socket = tokio::net::TcpSocket::new_v4()?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        chat2local_agent_platform::exclusive_socket(socket.as_raw_socket())?;
    }
    socket.bind(std::net::SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        options.port,
    )))?;
    let listener = Arc::new(socket.listen(128)?);
    let admission = crate::http::Admission::new();
    let accepting = {
        let listener = listener.clone();
        let admission = admission.clone();
        tokio::spawn(async move { crate::http::serve(&listener, admission).await })
    };
    let port = options.port;
    #[cfg(feature = "fixture")]
    let hooks = options.hooks.clone();
    let initial = match tokio::task::spawn_blocking(move || crate::startup(&options)).await {
        Ok(Ok(initial)) => initial,
        result => {
            admission.close();
            let _ = accepting.await;
            return Err(match result {
                Ok(Err(e)) => e,
                _ => Error::new(503, "Controller startup failed."),
            });
        }
    };
    let store = Arc::new(initial.store);
    let persistence = Persistence::new(
        store.clone(),
        #[cfg(feature = "fixture")]
        hooks.clone(),
    );
    let (jobs, mut receive) = mpsc::channel::<Job>(24);
    let (effects, effect_receiver) = mpsc::channel(64);
    let bridge_stop = watch::channel(false).0;
    let host = Arc::new(Host {
        workflows: crate::workflow::Service::new(),
        platform: initial.platform,
        network: crate::network::Service::new(initial.bridge),
        core: Mutex::new(Lifecycle::default()),
        state: Mutex::new(State {
            config: initial.config,
            secrets: initial.secrets,
            epoch: 0,
            last_remote: None,
            bridge_warning: None,
            guide_warning: None,
            guide_session: None,
            guide_remote: None,
            persistence_warning: None,
            terminal_available: false,
            operations_healthy: true,
            audit: Default::default(),
        }),
        terminal: crate::terminal::Service::new(
            store.clone(),
            #[cfg(feature = "fixture")]
            hooks.clone(),
        ),
        store,
        persistence,
        sessions: Mutex::new(management::Sessions::new()),
        origin: initial.origin,
        token: initial.token,
        instance: initial.instance,
        active: AtomicBool::new(false),
        closing: AtomicBool::new(false),
        fault: AtomicBool::new(false),
        fault_applied: AtomicBool::new(false),
        authentication: Arc::new(Semaphore::new(8)),
        jobs,
        effects,
        bridge_stop,
        admission: admission.clone(),
        pending: AtomicUsize::new(0),
        drained: Notify::new(),
        recovery: Semaphore::new(24),
        #[cfg(feature = "fixture")]
        hooks,
    });
    host.lock_state().terminal_available = host.terminal.available();
    let weak = Arc::downgrade(&host);
    let worker = tokio::spawn(async move {
        while let Some(job) = receive.recv().await {
            let Some(host) = weak.upgrade() else { break };
            let ticket = job.ticket().to_owned();
            let owner = host.clone();
            let outcome = tokio::spawn(async move {
                let host = owner;
                let mut local = None;
                let mut remote = None;
                let mut workflow = None;
                match job {
                    Job::Workflow { work, reply, .. } => {
                        workflow = Some((reply, work(host.clone()).await));
                    }
                    Job::Http { request, reply, .. } => {
                        let result = controller::execute(&host, request, false)
                            .await
                            .unwrap_or_else(Reply::error);
                        local = Some((reply, result));
                    }
                    Job::Remote { call, socket, .. } => {
                        remote = bridge::dispatch(&host, call, socket).await;
                    }
                }
                (local, remote, workflow)
            })
            .await;
            let (local, remote, workflow) = match outcome {
                Ok(value) => value,
                Err(_) => {
                    host.poison();
                    (None, None, None)
                }
            };
            if !host.faulted() {
                let _ = host.command(json!({"op":"finish","ticket":ticket}));
            }
            // Confirmed local work survives a later finish fault. Remote sends recheck the latch.
            if let Some((reply, result)) = local {
                let _ = reply.send(result);
            }
            if let Some((reply, result)) = workflow {
                let _ = reply.send(result);
            }
            if let Some(remote) = remote {
                remote.deliver(&host).await;
            }
            host.pending.fetch_sub(1, Ordering::SeqCst);
            host.drained.notify_one();
        }
    });
    let bridge = tokio::spawn(bridge::run(Arc::downgrade(&host), effect_receiver));
    let removal_retry = tokio::spawn(crate::sharing::retry_removals(Arc::downgrade(&host)));
    host.command(json!({"op":"activate"}))?;
    host.active.store(true, Ordering::SeqCst);
    *admission.host.lock().unwrap() = Arc::downgrade(&host);
    let identity = crate::tools::identity(&host.lock_state().secrets).is_ok();
    host.command(
        json!({"op":"bridgeStart","hasIdentity":identity,"now":management::now() as u64}),
    )?;
    on_ready(Ready {
        origin: host.origin.clone(),
        instance_id: host.instance.clone(),
        port,
        #[cfg(feature = "fixture")]
        control: crate::fixture::Control {
            host: Arc::downgrade(&host),
            hooks: host.hooks.clone(),
        },
    });
    let result = accepting
        .await
        .map_err(|_| Error::new(503, "Controller listener failed."))?;
    host.close();
    let _ = removal_retry.await;
    host.workflows.drain().await;
    host.drain().await;
    host.persistence.drain().await;
    host.terminal.drain().await;
    host.network.drain().await;
    host.platform.drain().await;
    let _ = bridge.await;
    if !host.faulted() {
        host.command(json!({"op":"finishClose"}))?;
    }
    drop(listener);
    drop(host);
    let _ = worker.await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn workflow_transport_poll_gate_rechecks_typed_pending_identity_and_cancellation() {
        use crate::workflow::{Guard, Slot};
        for slot in [
            Slot::Active,
            Slot::EnrollmentPending,
            Slot::AccountEnrollmentPending,
        ] {
            for cause in [
                "origin",
                "deviceId",
                "deviceKey",
                "slot",
                "paused",
                "selection",
                "revision",
                "disconnect",
                "close",
            ] {
                let host = Arc::new(test_host());
                host.active.store(true, Ordering::SeqCst);
                let identity = json!({"origin":"http://127.0.0.1:9","deviceId":"a".repeat(32),"deviceKey":"b".repeat(64)});
                let mut secrets = json!({});
                secrets[slot.key()] = identity.clone();
                host.lock_state().secrets = value::parse(secrets.to_string().as_bytes()).unwrap();
                let (disconnect, receive) = watch::channel(false);
                let mut guard = Guard::capture(&host, receive, false).unwrap();
                guard.credential = Some((
                    slot,
                    crate::workflow::identity_at(&host.lock_state().secrets, slot).unwrap(),
                ));
                guard.selection = Some(host.platform.selection_revision());
                let prepared = host
                    .network
                    .prepare(&host, "http://127.0.0.1:9", false)
                    .await
                    .unwrap();
                let gate = host
                    .network
                    .guard_workflow(Arc::downgrade(&host), prepared, guard);
                let mut polls = 0;
                assert!(gate(&mut || polls += 1));
                assert_eq!(polls, 1);
                match cause {
                    "origin" | "deviceId" | "deviceKey" => {
                        secrets[slot.key()][cause] = json!(match cause {
                            "origin" => "http://127.0.0.1:10".into(),
                            "deviceId" => "c".repeat(32),
                            _ => "d".repeat(64),
                        });
                        host.lock_state().secrets =
                            value::parse(secrets.to_string().as_bytes()).unwrap();
                    }
                    "slot" => {
                        secrets.as_object_mut().unwrap().remove(slot.key());
                        secrets[if slot == Slot::Active {
                            "accountEnrollmentPending"
                        } else {
                            "identity"
                        }] = identity;
                        host.lock_state().secrets =
                            value::parse(secrets.to_string().as_bytes()).unwrap();
                    }
                    "paused" => value::put(
                        &mut host.lock_state().config,
                        "paused",
                        chat2local_js_value_compat::Value::Bool(true),
                    )
                    .unwrap(),
                    "selection" => {
                        host.platform.cancel_picker();
                    }
                    "revision" => host.workflows.cancel(),
                    "disconnect" => {
                        disconnect.send_replace(true);
                    }
                    "close" => {
                        host.closing.store(true, Ordering::SeqCst);
                    }
                    _ => unreachable!(),
                }
                assert!(!gate(&mut || polls += 1), "{slot:?}/{cause}");
                assert_eq!(
                    polls, 1,
                    "a denied gate must not poll or submit credentials"
                );
            }
        }
    }
    fn test_host() -> Host {
        let store = Arc::new(Store::new(
            std::env::temp_dir().join("unused-close-notification-test"),
        ));
        #[cfg(feature = "fixture")]
        let hooks = Arc::new(crate::fixture::Hooks::default());
        let persistence = Persistence::new(
            store.clone(),
            #[cfg(feature = "fixture")]
            hooks.clone(),
        );
        let admission = crate::http::Admission::new();
        Host {
            workflows: crate::workflow::Service::new(),
            platform: crate::platform::Service::new(
                #[cfg(feature = "fixture")]
                Default::default(),
            )
            .unwrap(),
            network: crate::network::Service::new(crate::network::Config::test()),
            core: Mutex::new(Lifecycle::default()),
            state: Mutex::new(State {
                config: value::parse(br#"{"paused":false,"roots":[]}"#).unwrap(),
                secrets: value::parse(b"{}").unwrap(),
                epoch: 0,
                last_remote: None,
                bridge_warning: None,
                guide_warning: None,
                guide_session: None,
                guide_remote: None,
                persistence_warning: None,
                terminal_available: false,
                operations_healthy: true,
                audit: Default::default(),
            }),
            terminal: crate::terminal::Service::new(
                store.clone(),
                #[cfg(feature = "fixture")]
                hooks.clone(),
            ),
            store,
            persistence,
            sessions: Mutex::new(management::Sessions::new()),
            origin: String::new(),
            token: String::new(),
            instance: String::new(),
            active: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            fault: AtomicBool::new(false),
            fault_applied: AtomicBool::new(false),
            authentication: Arc::new(Semaphore::new(8)),
            jobs: mpsc::channel(24).0,
            effects: mpsc::channel(64).0,
            bridge_stop: watch::channel(false).0,
            admission: admission.clone(),
            pending: AtomicUsize::new(0),
            drained: Notify::new(),
            recovery: Semaphore::new(24),
            #[cfg(feature = "fixture")]
            hooks,
        }
    }
    #[tokio::test]
    async fn close_keeps_notification_for_next_accept_waiter() {
        let host = test_host();
        let admission = host.admission.clone();
        assert!(!admission.closed.load(Ordering::SeqCst));
        host.close();
        assert!(admission.closed.load(Ordering::SeqCst));
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            admission.stopped.notified(),
        )
        .await
        .expect("Actual close must retain a permit for the future accept waiter.");
    }
    #[tokio::test]
    async fn failed_core_latches_before_blocked_pause_overlay_and_recovery_forces_pause() {
        let host = Arc::new(test_host());
        let state = host.state.lock().unwrap();
        let other = host.clone();
        let failed = std::thread::spawn(move || other.command(json!({"op":"invalid"})));
        let end = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !host.faulted() && std::time::Instant::now() < end {
            std::thread::yield_now();
        }
        assert!(host.faulted());
        assert_eq!(
            value::boolean(&state.config, value::prop(&state.config, "paused")),
            Some(false)
        );
        // Hold the exact state mutex that prevents poison's pause overlay.
        let input = value::parse(br#"{"id":"00000000-0000-0000-0000-000000000000"}"#).unwrap();
        let (restricted, _, _) =
            controller::mutation(&state.config, "/api/root/remove", &input, host.faulted())
                .unwrap();
        assert_eq!(
            value::boolean(&restricted, value::prop(&restricted, "paused")),
            Some(true)
        );
        {
            let mut core = host.core.lock().unwrap();
            assert!(
                host.execute_locked(&mut core, &json!({"op":"snapshot"}))
                    .is_err()
            );
            assert!(host.faulted());
        }
        drop(state);
        assert!(failed.join().unwrap().is_err());
        let state = host.state.lock().unwrap();
        assert_eq!(
            value::boolean(&state.config, value::prop(&state.config, "paused")),
            Some(true)
        );
    }
    #[tokio::test]
    async fn authenticated_status_reads_poisoned_state_before_pause_overlay() {
        let mut host = test_host();
        host.origin = "http://127.0.0.1:12345".into();
        host.token = "a".repeat(64);
        host.active.store(true, Ordering::SeqCst);
        let host = Arc::new(host);
        let other = host.clone();
        assert!(
            std::thread::spawn(move || {
                let mut core = other.core.lock().unwrap();
                let _state = other.state.lock().unwrap();
                other.latch_while_locked(&mut core);
                panic!("Owned poisoned-state interval before worker cleanup");
            })
            .join()
            .is_err()
        );
        assert!(host.faulted());
        assert!(host.state.is_poisoned());
        assert!(!host.fault_applied.load(Ordering::SeqCst));
        let request = Request {
            selection: None,
            disconnected: watch::channel(false).1,
            method: "GET".into(),
            target: "/api/status".into(),
            body: Vec::new(),
            headers: vec![
                ("host".into(), "127.0.0.1:12345".into()),
                ("x-chat2local-token".into(), host.token.clone()),
            ],
        };
        let reply = controller::execute(&host, request, true).await.unwrap();
        assert_eq!(reply.status, 200);
        let status: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
        assert_eq!(status["nativeFault"], true);
        assert_eq!(status["paused"], true);
        assert!(!host.fault_applied.load(Ordering::SeqCst));
        let state = host.state.lock().unwrap_or_else(|e| e.into_inner());
        let input = value::parse(br#"{"id":"00000000-0000-0000-0000-000000000000"}"#).unwrap();
        let (next, _, _) =
            controller::mutation(&state.config, "/api/root/remove", &input, host.faulted())
                .unwrap();
        assert_eq!(
            value::boolean(&next, value::prop(&next, "paused")),
            Some(true)
        );
        drop(state);
        host.poison();
        assert!(!host.state.is_poisoned());
    }
}
