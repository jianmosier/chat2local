//! One Host-owned network preparation authority; established sockets keep Bridge ownership.
use crate::{Error, Options, Result, network_query, runtime::Host, tools, value};
use chat2local_agent_transport::{
    Attempt, AttemptOwner, NetworkMode, NetworkSettings, PublicationGate, RoutePlan, StartupTls,
    Target, TlsProfile, Transport,
};
use chat2local_js_value_compat::{Document, Value as J};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Notify, watch};
pub struct Config {
    pub transport: Transport,
    query: std::sync::Mutex<crate::network_query::Mode>,
    env: BTreeMap<String, String>,
    system: Option<String>,
}
pub fn origin(raw: &str) -> Result<String> {
    let parsed = url::Url::parse(raw).map_err(|_| Error::new(400, "Invalid relay origin."))?;
    let host = parsed.host_str().unwrap_or("");
    let local = ["localhost", "[::1]", "127.0.0.1"].contains(&host);
    if !["http", "https"].contains(&parsed.scheme())
        || parsed.scheme() == "http" && !local
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(Error::new(400, "Invalid relay origin."));
    }
    Ok(parsed.origin().ascii_serialization())
}
pub fn settings(doc: &Document) -> Result<NetworkSettings> {
    value::fields(doc, &["mode", "proxy"])?;
    let mode = value::string(doc, value::prop(doc, "mode"))
        .ok_or_else(|| Error::new(400, "请选择自动、直连或指定代理。"))?;
    let mode = match mode.as_str() {
        "auto" => NetworkMode::Auto,
        "direct" => NetworkMode::Direct,
        "proxy" => NetworkMode::Proxy,
        _ => return Err(Error::new(400, "请选择自动、直连或指定代理。")),
    };
    let proxy = if mode == NetworkMode::Proxy {
        let raw = value::string(doc, value::prop(doc, "proxy"))
            .ok_or_else(|| Error::new(400, "Invalid proxy address."))?;
        if raw.encode_utf16().count() > 2048 {
            return Err(Error::new(400, "Invalid proxy address."));
        }
        chat2local_agent_transport::Proxy::parse(&raw, false)
            .map_err(|_| Error::new(400, "Invalid proxy address."))?;
        Some(
            url::Url::parse(&raw)
                .map_err(|_| Error::new(400, "Invalid proxy address."))?
                .as_str()
                .trim_end_matches('/')
                .to_owned(),
        )
    } else {
        None
    };
    Ok(NetworkSettings { mode, proxy })
}
pub fn saved(config: &Document) -> Result<NetworkSettings> {
    match value::prop(config, "network") {
        None => Ok(NetworkSettings::default()),
        Some(id) if matches!(config.value(id)?, J::Null | J::Undefined) => {
            Ok(NetworkSettings::default())
        }
        Some(id) => settings(&value::parse(value::subtree(config, id)?.as_bytes())?),
    }
}
fn selected_origin(
    config: &Document,
    secrets: &Document,
    input: Option<&Document>,
) -> Result<Option<String>> {
    let identity = value::prop(secrets, "identity");
    let saved_origin = identity.and_then(|id| value::get(secrets, id, "origin"));
    let candidates = [
        (secrets, saved_origin),
        (config, value::prop(config, "relay")),
    ];
    for (doc, id) in candidates
        .into_iter()
        .chain(input.map(|doc| (doc, value::prop(doc, "origin"))))
    {
        if value::truthy(doc, id) {
            return value::string(doc, id)
                .map(Some)
                .ok_or_else(|| Error::new(400, "Invalid relay origin."));
        }
    }
    Ok(None)
}
fn stale() -> Error {
    Error::new(503, "网络检测已被新设置替代，请重新连接。")
}
#[derive(Clone)]
pub struct Prepared {
    pub plan: RoutePlan,
    pub profile: TlsProfile,
    pub origin: String,
    settings: NetworkSettings,
    pub revision: u64,
}
struct Cached {
    value: Arc<Prepared>,
    checked: Instant,
}
type Outcome = Option<Result<Arc<Prepared>>>;
struct Pending {
    key: String,
    receive: watch::Receiver<Outcome>,
}
struct State {
    revision: u64,
    closed: bool,
    cached: Option<Cached>,
    tls: Option<Arc<Prepared>>,
    pending: Option<Pending>,
    status: Value,
}
pub struct Service {
    pub config: Config,
    state: Mutex<State>,
    owner: AttemptOwner,
    revision: watch::Sender<u64>,
    pending: AtomicUsize,
    drained: Notify,
    pub query: Arc<network_query::Observations>,
}
impl Service {
    #[cfg(feature = "fixture")]
    pub async fn system_query(self: &Arc<Self>, host: &Arc<Host>, raw: &str) -> Result<Value> {
        let origin = origin(raw)?;
        let (send, receive) = tokio::sync::oneshot::channel();
        let revision = {
            let state = self.state.lock().unwrap();
            if state.closed || self.pending() >= 4 {
                return Err(stale());
            }
            self.pending.fetch_add(1, Ordering::SeqCst);
            state.revision
        };
        let service = self.clone();
        let hooks = host.hooks.clone();
        tokio::spawn(async move {
            let result=network_query::query(origin,network_query::Mode::default(),service.revision.subscribe(),revision,service.query.clone(),hooks).await.map(|proxy|json!({"source":if proxy.is_empty(){"system-direct"}else{"system-proxy"},"actualSystemQuery":true}));
            let _ = send.send(result);
            service.pending.fetch_sub(1, Ordering::SeqCst);
            service.drained.notify_one();
        });
        receive.await.map_err(|_| stale())?
    }
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: Mutex::new(State {
                revision: 0,
                closed: false,
                cached: None,
                tls: None,
                pending: None,
                status: json!({"mode":"auto","source":"not-checked","error":null}),
            }),
            owner: AttemptOwner::new(0),
            revision: watch::channel(0).0,
            pending: AtomicUsize::new(0),
            drained: Notify::new(),
            query: Arc::new(Default::default()),
        })
    }
    pub fn status(&self) -> Value {
        self.state.lock().unwrap().status.clone()
    }
    #[cfg(feature = "fixture")]
    pub fn revision(&self) -> u64 {
        self.state.lock().unwrap().revision
    }
    pub fn invalidate(&self) {
        let mut state = self.state.lock().unwrap();
        state.revision += 1;
        state.cached = None;
        state.pending = None;
        self.owner.revise(state.revision);
        self.revision.send_replace(state.revision);
    }
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.revision += 1;
        state.cached = None;
        state.pending = None;
        self.owner.close();
        self.revision.send_replace(state.revision);
    }
    pub fn pending(&self) -> usize {
        self.pending.load(Ordering::SeqCst)
    }
    pub async fn drain(&self) {
        while self.pending() != 0 {
            self.drained.notified().await;
        }
    }
    pub fn current(&self, p: &Prepared) -> bool {
        let state = self.state.lock().unwrap();
        !state.closed && state.revision == p.revision
    }
    pub fn attempt(&self, p: &Prepared) -> Result<Attempt> {
        let a = self.owner.attempt();
        if !self.current(p) {
            return Err(stale());
        }
        Ok(a)
    }
    pub fn guard(
        self: &Arc<Self>,
        host: Weak<Host>,
        p: Arc<Prepared>,
        identity: Option<tools::Identity>,
        bridge: Option<Value>,
    ) -> PublicationGate {
        self.guard_scoped(host, p, identity, bridge, None)
    }
    pub fn guard_workflow(
        self: &Arc<Self>,
        host: Weak<Host>,
        p: Arc<Prepared>,
        guard: crate::workflow::Guard,
    ) -> PublicationGate {
        self.guard_scoped(host, p, None, None, Some(guard))
    }
    fn guard_scoped(
        self: &Arc<Self>,
        host: Weak<Host>,
        p: Arc<Prepared>,
        identity: Option<tools::Identity>,
        bridge: Option<Value>,
        workflow: Option<crate::workflow::Guard>,
    ) -> PublicationGate {
        let service = self.clone();
        Arc::new(move |poll| {
            let Some(host) = host.upgrade() else {
                return false;
            };
            let mut core = host.core.lock().unwrap_or_else(|e| e.into_inner());
            if host.faulted() || host.closing.load(Ordering::SeqCst) {
                return false;
            }
            if let Some(token) = &bridge {
                let snapshot = host.execute_locked(&mut core, &json!({"op":"snapshot"}));
                if snapshot.as_ref().is_err() {
                    drop(core);
                    host.poison();
                    return false;
                }
                let snapshot = snapshot.unwrap();
                if snapshot["result"]["bridge"]["generation"] != token["generation"]
                    || snapshot["result"]["bridge"]["attempt"] != token["attempt"]
                {
                    return false;
                }
            }
            let state = host.lock_state();
            let disconnected = workflow.as_ref().map(|g| g.disconnected.borrow());
            let workflow_state = workflow
                .as_ref()
                .map(|_| host.workflows.inner.lock().unwrap());
            if let Some(g) = &workflow
                && (disconnected.as_ref().is_some_and(|v| **v)
                    || g.check(&host, &state, workflow_state.as_ref().unwrap())
                        .is_err())
            {
                return false;
            }
            if saved(&state.config).ok().as_ref() != Some(&p.settings)
                || identity
                    .as_ref()
                    .is_some_and(|id| tools::identity(&state.secrets).ok().as_ref() != Some(id))
            {
                return false;
            }
            let network = service.state.lock().unwrap();
            if network.closed || network.revision != p.revision {
                return false;
            }
            host.platform
                .with_selection(workflow.as_ref().and_then(|g| g.selection), |current| {
                    if current {
                        poll();
                    }
                    current
                })
        })
    }
    pub async fn prepare(
        self: &Arc<Self>,
        host: &Arc<Host>,
        raw: &str,
        force: bool,
    ) -> Result<Arc<Prepared>> {
        let origin = origin(raw)?;
        let selected = saved(&host.lock_state().config)?;
        let key =
            serde_json::to_string(&(serde_json::to_value(&selected).unwrap(), &origin)).unwrap();
        let mut receive = {
            let mut state = self.state.lock().unwrap();
            if state.closed || host.faulted() || host.closing.load(Ordering::SeqCst) {
                return Err(stale());
            }
            if !force
                && let Some(c) = &state.cached
                && c.value.origin == origin
                && c.value.settings == selected
                && c.checked.elapsed() < Duration::from_secs(30)
            {
                return Ok(c.value.clone());
            }
            if !force
                && let Some(p) = &state.pending
                && p.key == key
            {
                p.receive.clone()
            } else {
                if self.pending() >= 4 {
                    return Err(Error::new(503, "Network preparation capacity unavailable."));
                }
                state.revision += 1;
                let revision = state.revision;
                state.cached = None;
                self.owner.revise(revision);
                self.revision.send_replace(revision);
                let (send, receive) = watch::channel(None);
                state.pending = Some(Pending {
                    key,
                    receive: receive.clone(),
                });
                let previous = state.tls.clone();
                let owner = host.clone();
                let service = self.clone();
                self.pending.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let result = service
                        .resolve(&owner, origin, selected.clone(), revision, previous)
                        .await;
                    let compatible = saved(&owner.lock_state().config).is_ok_and(|s| s == selected)
                        && !owner.faulted()
                        && !owner.closing.load(Ordering::SeqCst);
                    let mut state = service.state.lock().unwrap();
                    let result = if !compatible || state.closed || state.revision != revision {
                        Err(stale())
                    } else {
                        result
                    };
                    if state.revision == revision {
                        state.pending = None;
                        match &result {
                            Ok(p) => {
                                state.status = json!({"mode":p.settings.mode,"source":p.plan.source(),"tlsProfile":p.profile,"error":null});
                                state.cached = Some(Cached {
                                    value: p.clone(),
                                    checked: Instant::now(),
                                });
                                state.tls = Some(p.clone());
                            }
                            Err(e) => {
                                state.cached = None;
                                state.status = json!({"mode":selected.mode,"source":"error","error":e.message});
                            }
                        }
                    }
                    send.send_replace(Some(result));
                    drop(state);
                    service.pending.fetch_sub(1, Ordering::SeqCst);
                    service.drained.notify_one();
                });
                receive
            }
        };
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                if let Some(result) = receive.borrow().clone() {
                    return result;
                }
                receive.changed().await.map_err(|_| stale())?;
            }
        })
        .await
        .map_err(|_| Error::new(503, "Network preparation remains pending."))?
    }
    async fn resolve(
        self: &Arc<Self>,
        host: &Arc<Host>,
        origin: String,
        selected: NetworkSettings,
        revision: u64,
        previous: Option<Arc<Prepared>>,
    ) -> Result<Arc<Prepared>> {
        let target = Target::parse(&origin).map_err(|_| stale())?;
        let mut plan = chat2local_agent_transport::prepare(
            &selected,
            &target,
            &self.config.env,
            self.config.system.as_deref(),
            revision,
        );
        if plan.is_err() && selected.mode == NetworkMode::Auto && self.config.system.is_none() {
            // Discovery is only needed after pure policy establishes that no explicit
            // environment route exists. Never fall back after invalid explicit proxy.
            let explicit = [
                "http_proxy",
                "HTTP_PROXY",
                "https_proxy",
                "HTTPS_PROXY",
                "all_proxy",
                "ALL_PROXY",
            ]
            .iter()
            .any(|k| self.config.env.get(*k).is_some_and(|s| !s.is_empty()));
            if !explicit {
                let mode = self.config.query.lock().unwrap().clone();
                let decision = network_query::query(
                    origin.clone(),
                    mode,
                    self.revision.subscribe(),
                    revision,
                    self.query.clone(),
                    #[cfg(feature = "fixture")]
                    host.hooks.clone(),
                )
                .await?;
                plan = chat2local_agent_transport::prepare(
                    &selected,
                    &target,
                    &self.config.env,
                    Some(&decision),
                    revision,
                );
            }
        }
        let plan =
            plan.map_err(|_| Error::new(400, "Network policy failed; no fallback was attempted."))?;
        let mut p = Prepared {
            plan,
            profile: TlsProfile::Default,
            origin,
            settings: selected,
            revision,
        };
        if let Some(previous) =
            previous.filter(|old| old.origin == p.origin && old.plan.same_route(&p.plan))
        {
            p.profile = previous.profile;
        } else if target.secure() && p.plan.has_proxy() {
            let snapshot = Arc::new(p.clone());
            let mut attempt = self.attempt(&p)?;
            attempt.set_publication_gate(self.guard(Arc::downgrade(host), snapshot, None, None));
            p.profile = self
                .config
                .transport
                .select_probe_profile(&p.plan, &target, &mut attempt)
                .await
                .map_err(|e| Error::new(400, e.to_string()))?;
        }
        if !self.current(&p) {
            return Err(stale());
        }
        Ok(Arc::new(p))
    }
    #[cfg(feature = "fixture")]
    pub fn query_mode(&self, mode: network_query::Mode) -> Result<()> {
        mode.validate()?;
        *self.config.query.lock().unwrap() = mode;
        Ok(())
    }
}
impl Config {
    #[cfg(test)]
    pub fn test() -> Self {
        Self {
            transport: Transport::new(StartupTls::from_environment(&BTreeMap::new()).unwrap()),
            env: BTreeMap::new(),
            system: Some(String::new()),
            query: Mutex::new(Default::default()),
        }
    }
    pub fn new(_options: &Options) -> Result<Self> {
        #[cfg(feature = "fixture")]
        if let Some(mode) = &_options.transport.system_query {
            mode.validate()?;
        }
        #[cfg(feature = "fixture")]
        let env = _options.transport.env.clone();
        #[cfg(not(feature = "fixture"))]
        let env = std::env::vars().collect();
        #[cfg(feature = "fixture")]
        let tls = if let Some(ca) = &_options.transport.ca {
            StartupTls::fixture_with_ca(&env, ca.as_bytes())
        } else {
            StartupTls::from_environment(&env)
        };
        #[cfg(not(feature = "fixture"))]
        let tls = StartupTls::from_environment(&env);
        let tls = tls.map_err(|_| Error::new(503, "Native transport TLS policy unavailable."))?;
        #[cfg(feature = "fixture")]
        let transport = if _options.transport.addresses.is_empty() {
            Transport::new(tls)
        } else {
            Transport::fixture(tls, _options.transport.addresses.clone())
                .map_err(|_| Error::new(400, "Invalid synthetic network addresses."))?
        };
        #[cfg(not(feature = "fixture"))]
        let transport = Transport::new(tls);
        #[cfg(feature = "fixture")]
        let system = _options.transport.system.clone();
        #[cfg(not(feature = "fixture"))]
        let system = None;
        Ok(Self {
            transport,
            query: std::sync::Mutex::new({
                #[cfg(feature = "fixture")]
                {
                    _options.transport.system_query.clone().unwrap_or_default()
                }
                #[cfg(not(feature = "fixture"))]
                {
                    crate::network_query::Mode::default()
                }
            }),
            env,
            system,
        })
    }
}
pub async fn action(host: &Arc<Host>, action: &str, input: &Document) -> Result<Value> {
    if action == "/api/network/set" {
        let selected = settings(input)?;
        host.command(json!({"op":"invalidateSelection"}))?;
        host.command(json!({"op":"bridgeStop"}))?;
        host.network.invalidate();
        let (receive, epoch, previous) = {
            let mut state = host.lock_state();
            if host.faulted() || host.closing.load(Ordering::SeqCst) {
                return Err(stale());
            }
            crate::operations::cancel_pending(&mut state);
            let previous = state.config.try_clone()?;
            let mut next = state.config.try_clone()?;
            let id = next.import(
                value::parse(serde_json::to_string(&selected).unwrap().as_bytes())?,
                usize::MAX,
            )?;
            next.set_property(next.root(), "network".encode_utf16().collect(), id)?;
            // The selected policy is effective before enqueue: any later fault
            // restriction derives from it and remains ordered after this save.
            let receive = host.persistence.config(next.try_clone()?)?;
            state.config = next;
            state.epoch += 1;
            (receive, state.epoch, previous)
        };
        if let Err(error) = crate::persistence::confirmed(receive, false).await {
            let mut state = host.lock_state();
            if state.epoch == epoch && !host.faulted() && !host.closing.load(Ordering::SeqCst) {
                state.config = previous;
                state.epoch += 1;
            }
            return Err(error);
        }
        let (relay, identity) = {
            let state = host.lock_state();
            if host.faulted() || host.closing.load(Ordering::SeqCst) || state.epoch != epoch {
                return Err(stale());
            }
            let identity = tools::identity(&state.secrets).ok();
            (
                selected_origin(&state.config, &state.secrets, None)?,
                identity.is_some(),
            )
        };
        if let Some(relay) = relay {
            host.network.prepare(host, &relay, true).await?;
        }
        if !host.faulted()
            && !host.closing.load(Ordering::SeqCst)
            && host.lock_state().epoch == epoch
        {
            host.command(json!({"op":"bridgeStart","hasIdentity":identity,"now":crate::management::now() as u64}))?;
        } else {
            return Err(stale());
        }
        return Ok(json!({"ok":true,"settings":selected,"network":host.network.status()}));
    }
    value::fields(input, &["origin"])?;
    let (relay, identity) = {
        let state = host.lock_state();
        let identity = tools::identity(&state.secrets).ok();
        let relay = selected_origin(&state.config, &state.secrets, Some(input))?
            .ok_or_else(|| Error::new(400, "Invalid relay origin."))?;
        (relay, identity)
    };
    let p = host.network.prepare(host, &relay, true).await?;
    let target = Target::parse(&format!("{}/healthz", p.origin)).map_err(|_| stale())?;
    let mut attempt = host.network.attempt(&p)?;
    attempt.set_publication_gate(host.network.guard(
        Arc::downgrade(host),
        p.clone(),
        identity,
        None,
    ));
    let result = host
        .network
        .config
        .transport
        .request_once(
            &p.plan,
            &target,
            p.profile,
            chat2local_agent_transport::HttpRequest::default(),
            chat2local_agent_transport::Limits {
                timeout: Duration::from_secs(10),
                body_bytes: 512 * 1024,
            },
            &mut attempt,
        )
        .await;
    let connection_error =
        "无法连接中继，请检查直连／代理设置及代理是否运行。没有自动改用其他网络。";
    let (ok, message) = match result {
        Ok(r) => {
            let body = value::parse(String::from_utf8_lossy(&r.body).as_bytes());
            let failed = matches!(r.status, 301 | 302 | 303 | 307 | 308)
                || (200..300).contains(&r.status)
                    && body
                        .as_ref()
                        .map_or(true, |v| matches!(v.value(v.root()), Ok(J::Null)));
            let healthy = (200..300).contains(&r.status)
                && body.is_ok_and(|v| {
                    value::string(&v, value::prop(&v, "name")).as_deref()
                        == Some("chat2local-relay")
                });
            (
                healthy,
                if failed {
                    connection_error
                } else if healthy {
                    "中继网络可达；这不代表已完成 ChatGPT 官网授权。"
                } else {
                    "入口响应不匹配，请核对中继地址。"
                },
            )
        }
        Err(_) => (false, connection_error),
    };
    Ok(
        json!({"ok":ok,"network":host.network.status(),"websiteClientVerified":false,"message":message}),
    )
}
