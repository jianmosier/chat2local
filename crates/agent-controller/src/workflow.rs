//! Host-owned local workflows. Network and human waits stay outside FIFO;
//! short durable transitions enter the same bounded queue as ordinary work.
use crate::{
    Error, Reply, Request, Result,
    runtime::{Host, State},
    value,
    workflow_value::Doc,
};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Notify, oneshot, watch};
pub type Commit =
    Box<dyn FnOnce(Arc<Host>) -> Pin<Box<dyn Future<Output = Result<Doc>> + Send>> + Send>;
struct Page {
    profile: String,
    until: f64,
    flows: HashSet<String>,
}
struct Running {
    fingerprint: String,
    limit: usize,
    receive: watch::Receiver<Option<Result<String>>>,
}
pub struct Inner {
    pub revision: u64,
    pub closed: bool,
    pages: HashMap<String, Page>,
    running: HashMap<String, Running>,
    pub setup: bool,
    pub previews: HashMap<String, Doc>,
    pub tickets: HashMap<String, (f64, String)>,
    pub setup_info: String,
}
pub struct Service {
    pub inner: Mutex<Inner>,
    pub changed: watch::Sender<u64>,
    active: AtomicUsize,
    drained: Notify,
}
impl Service {
    pub fn new() -> Arc<Self> {
        Arc::new(Self{inner:Mutex::new(Inner{revision:0,closed:false,pages:HashMap::new(),running:HashMap::new(),setup:false,previews:HashMap::new(),tickets:HashMap::new(),setup_info:json!({"ready":false,"code":"NOT_CHECKED","message":"连接前将检查官方安装入口。"}).to_string()}),changed:watch::channel(0).0,active:AtomicUsize::new(0),drained:Notify::new()})
    }
    pub fn cancel(&self) {
        let mut s = self.inner.lock().unwrap();
        s.revision += 1;
        self.changed.send_replace(s.revision);
    }
    pub fn close(&self) {
        let mut s = self.inner.lock().unwrap();
        s.closed = true;
        s.revision += 1;
        self.changed.send_replace(s.revision);
    }
    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
    pub async fn drain(&self) {
        while self.active() != 0 {
            self.drained.notified().await;
        }
    }
    pub fn setup_active(&self) -> bool {
        self.inner.lock().unwrap().setup
    }
    pub fn page(&self, profile: &str, cookie: &str) -> Result<String> {
        let mut s = self.inner.lock().unwrap();
        s.pages.retain(|_, v| v.until > crate::management::now());
        let old = cookie_value(cookie, &format!("c2l_{profile}_local"));
        if let Some(v) = old.filter(|v| s.pages.get(v).is_some_and(|p| p.profile == profile)) {
            return Ok(v);
        }
        if s.pages.len() >= 32 {
            return Err(Error::new(429, "Too many local pages."));
        }
        let nonce = crate::random(32)?;
        s.pages.insert(
            nonce.clone(),
            Page {
                profile: profile.into(),
                until: crate::management::now() + 86400000.,
                flows: HashSet::new(),
            },
        );
        Ok(nonce)
    }
    pub fn session(
        &self,
        profile: &str,
        input: &Doc,
        cookie: &str,
        flow: Option<&str>,
    ) -> Result<String> {
        let nonce = input.req("nonce")?;
        let proof = cookie_value(cookie, &format!("c2l_{profile}_local"))
            .ok_or_else(|| Error::new(403, "Open the original local page."))?;
        if nonce.len() != 64
            || proof.len() != 64
            || !openssl::memcmp::eq(nonce.as_bytes(), proof.as_bytes())
        {
            return Err(Error::new(403, "Local page session required."));
        }
        let s = self.inner.lock().unwrap();
        let p = s
            .pages
            .get(&nonce)
            .filter(|p| p.profile == profile && p.until > crate::management::now())
            .ok_or_else(|| Error::new(403, "Local page expired."))?;
        if flow.is_some_and(|f| !p.flows.contains(f)) {
            return Err(Error::new(403, "Flow does not belong to this page."));
        }
        Ok(nonce)
    }
    pub fn bind(&self, nonce: &str, flow: &str) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .pages
            .get_mut(nonce)
            .ok_or_else(stale)?
            .flows
            .insert(flow.into());
        Ok(())
    }
    pub async fn coalesce(
        self: &Arc<Self>,
        host: &Arc<Host>,
        key: String,
        fingerprint: String,
        limit: usize,
        work: impl Future<Output = Result<Doc>> + Send + 'static,
    ) -> Result<Doc> {
        let mut receive = {
            let mut s = self.inner.lock().unwrap();
            if s.closed {
                return Err(stale());
            }
            if let Some(old) = s.running.get(&key) {
                if old.fingerprint != fingerprint
                    && !(key.starts_with("consent:") && fingerprint.is_empty())
                {
                    return Err(Error::new(
                        409,
                        "This request is already running with different input.",
                    ));
                }
                old.receive.clone()
            } else {
                if s.running.values().filter(|r| r.limit == limit).count() >= limit {
                    return Err(Error::new(429, "Local workflow capacity reached."));
                }
                let (send, receive) = watch::channel(None);
                s.running.insert(
                    key.clone(),
                    Running {
                        fingerprint,
                        limit,
                        receive: receive.clone(),
                    },
                );
                self.active.fetch_add(1, Ordering::SeqCst);
                let service = self.clone();
                let host = host.clone();
                tokio::spawn(async move {
                    let outcome = tokio::spawn(work)
                        .await
                        .unwrap_or_else(|_| {
                            host.poison();
                            Err(Error::new(503, "Local workflow failed."))
                        })
                        .and_then(|v| v.raw());
                    send.send_replace(Some(outcome));
                    service.inner.lock().unwrap().running.remove(&key);
                    service.active.fetch_sub(1, Ordering::SeqCst);
                    service.drained.notify_one();
                });
                receive
            }
        };
        loop {
            if let Some(result) = receive.borrow().clone() {
                return Doc::parse(&result?);
            }
            receive.changed().await.map_err(|_| stale())?;
        }
    }
}
pub fn cookie_value(cookie: &str, key: &str) -> Option<String> {
    let values = cookie
        .split(';')
        .filter_map(|x| x.trim().split_once('='))
        .filter(|(k, _)| *k == key)
        .map(|(_, v)| v.to_owned())
        .collect::<Vec<_>>();
    (values.len() == 1).then(|| values[0].clone())
}
pub fn stale() -> Error {
    Error::new(
        409,
        "Local authorization changed; continue the original request after checking its status.",
    )
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Slot {
    Active,
    EnrollmentPending,
    AccountEnrollmentPending,
}
impl Slot {
    pub fn key(self) -> &'static str {
        match self {
            Self::Active => "identity",
            Self::EnrollmentPending => "enrollmentPending",
            Self::AccountEnrollmentPending => "accountEnrollmentPending",
        }
    }
}
#[derive(Clone)]
pub struct Guard {
    pub revision: u64,
    pub policy: f64,
    pub allow_paused: bool,
    pub credential: Option<(Slot, crate::tools::Identity)>,
    pub disconnected: watch::Receiver<bool>,
    pub flow: Option<String>,
    pub selection: Option<u64>,
}
impl Guard {
    pub fn capture(
        host: &Host,
        disconnected: watch::Receiver<bool>,
        allow_paused: bool,
    ) -> Result<Self> {
        let _core = host.core.lock().unwrap_or_else(|e| e.into_inner());
        let state = host.lock_state();
        let service = host.workflows.inner.lock().unwrap();
        let g = Self {
            revision: service.revision,
            policy: policy(&state),
            allow_paused,
            credential: None,
            disconnected,
            flow: None,
            selection: None,
        };
        g.check(host, &state, &service)?;
        Ok(g)
    }
    pub fn check(&self, host: &Host, state: &State, service: &Inner) -> Result<()> {
        if host.faulted()
            || host.closing.load(Ordering::SeqCst)
            || service.closed
            || service.revision != self.revision
            || policy(state) != self.policy
            || !self.allow_paused
                && value::boolean(&state.config, value::prop(&state.config, "paused")) == Some(true)
        {
            return Err(stale());
        }
        if let Some((slot, id)) = &self.credential
            && identity_at(&state.secrets, *slot).ok().as_ref() != Some(id)
        {
            return Err(stale());
        }
        if let Some(raw) = &self.flow {
            let local = Doc::parse(raw)?;
            if local.has("policyDigest")
                && Some(crate::onboarding::policy_doc(
                    &Doc(state.config.try_clone()?),
                    &local,
                )?) != local.s("policyDigest")
            {
                return Err(stale());
            }
        }
        Ok(())
    }
    pub fn current(&self, host: &Host) -> Result<()> {
        let _core = host.core.lock().unwrap_or_else(|e| e.into_inner());
        let state = host.lock_state();
        let disconnected = self.disconnected.borrow();
        let service = host.workflows.inner.lock().unwrap();
        if *disconnected
            || self
                .selection
                .is_some_and(|r| r != host.platform.selection_revision())
        {
            return Err(stale());
        }
        self.check(host, &state, &service)
    }
    pub fn for_flow(&self, local: &Doc) -> Result<Self> {
        let mut g = self.clone();
        g.flow = Some(local.raw()?);
        Ok(g)
    }
}
pub fn policy(s: &State) -> f64 {
    value::number(&s.config, value::prop(&s.config, "accountPolicyRevision")).unwrap_or(0.)
}
pub fn identity_at(
    secrets: &chat2local_js_value_compat::Document,
    slot: Slot,
) -> Result<crate::tools::Identity> {
    let id = value::prop(secrets, slot.key()).ok_or_else(stale)?;
    let mut d = value::parse(b"{}")?;
    let id = d.import(
        value::parse(value::subtree(secrets, id)?.as_bytes())?,
        usize::MAX,
    )?;
    d.set_property(d.root(), "identity".encode_utf16().collect(), id)?;
    crate::tools::identity(&d)
}
pub enum Save {
    Config,
    Secrets,
    Private(String),
}
pub async fn save(
    host: &Arc<Host>,
    guard: Guard,
    kind: Save,
    next: Doc,
    held: Vec<Arc<chat2local_agent_platform::FolderBrowse>>,
) -> Result<()> {
    let owner = host.clone();
    let receive = host.persistence.submit(move |store| {
        let _held = held;
        let scope = |publish: &mut dyn FnMut() -> chat2local_native_store::Result<()>| {
            #[cfg(feature = "fixture")]
            {
                owner.hooks.wait("workflow:publish");
                let point = match &kind {
                    Save::Config => "workflow:publish:grant",
                    Save::Secrets => "workflow:publish:vault",
                    Save::Private(k) if k.starts_with("onboarding-flow-") => {
                        "workflow:publish:flow"
                    }
                    Save::Private(_) => "workflow:publish:intent",
                };
                owner.hooks.wait(point);
                owner
                    .hooks
                    .check("workflow:publish")
                    .and_then(|_| owner.hooks.check(point))
                    .map_err(|e| chat2local_native_store::Error::new("EIO", e.message))?;
                if let Save::Private(key) = &kind
                    && key.starts_with("onboarding-intent-")
                    && let Some(phase) = next.s("phase")
                    && ["confirming", "connected"].contains(&phase.as_str())
                {
                    let point = if phase == "confirming" {
                        "workflow:publish:confirmed"
                    } else {
                        "workflow:publish:connected"
                    };
                    owner.hooks.wait(point);
                    owner
                        .hooks
                        .check(point)
                        .map_err(|e| chat2local_native_store::Error::new("EIO", e.message))?;
                }
            }
            let _core = owner.core.lock().unwrap_or_else(|e| e.into_inner());
            let mut state = owner.lock_state();
            let disconnected = guard.disconnected.borrow();
            let service = owner.workflows.inner.lock().unwrap();
            // Retain both cancellation guards through the actual rename and memory install.
            guard
                .check(&owner, &state, &service)
                .map_err(|e| chat2local_native_store::Error::new("ECANCELLED", e.message))?;
            if *disconnected {
                return Err(chat2local_native_store::Error::new(
                    "ECANCELLED",
                    "Request disconnected.",
                ));
            }
            owner.platform.with_selection(guard.selection, |valid| {
                if !valid {
                    return Err(chat2local_native_store::Error::new(
                        "ECANCELLED",
                        "Selection was cancelled.",
                    ));
                }
                let installed = next
                    .0
                    .try_clone()
                    .map_err(|e| chat2local_native_store::Error::new("EINVALID", e.to_string()))?;
                publish()?;
                match &kind {
                    Save::Config => {
                        state.config = installed;
                        state.epoch += 1;
                    }
                    Save::Secrets => {
                        state.secrets = installed;
                        state.epoch += 1;
                    }
                    Save::Private(_) => {}
                }
                Ok(())
            })
        };
        let result = match &kind {
            Save::Config => store.save_config_scoped(&next.0, &scope),
            Save::Secrets => store.save_secrets_scoped(&next.0, &scope),
            Save::Private(key) => store.save_private_record_scoped(key, &next.0, &scope),
        };
        result.map_err(|e| {
            if e.code == "ECANCELLED" {
                stale()
            } else {
                Error::new(
                    503,
                    format!("Local persistence completion is not confirmed: {e}"),
                )
            }
        })
    })?;
    crate::persistence::confirmed(receive, false).await
}
pub async fn load(host: &Arc<Host>, key: String) -> Result<Option<Doc>> {
    let store = host.store.clone();
    tokio::task::spawn_blocking(move || {
        store
            .read_private_record(&key)
            .map(|v| v.map(Doc))
            .map_err(Error::from)
    })
    .await
    .map_err(|_| Error::new(503, "Private record read failed."))?
}
pub fn route(path: &str) -> bool {
    path.starts_with("/account-connect")
        || path.starts_with("/instance-connect")
        || path == "/connect"
        || path == "/connect/continue"
        || path.starts_with("/api/setup/")
        || path == "/api/instance/import-invitation"
        || path.starts_with("/api/shares/")
        || path.starts_with("/api/terminal/")
}
pub async fn execute(host: &Arc<Host>, request: Request, input: Option<Doc>) -> Result<Reply> {
    if request.target.starts_with("/account-connect")
        || request.target.starts_with("/instance-connect")
    {
        return crate::onboarding::handle(host, request, input).await;
    }
    if request.target.starts_with("/api/shares/") || request.target.starts_with("/api/terminal/") {
        return crate::sharing::handle(host, request, input.ok_or_else(stale)?).await;
    }
    crate::setup::handle(host, request, input).await
}
pub async fn commit(host: &Arc<Host>, work: Commit) -> Result<Doc> {
    let (reply, receive) = oneshot::channel();
    host.enqueue_workflow(work, reply)?;
    receive.await.map_err(|_| stale())?
}
pub fn reply(doc: Doc) -> Result<Reply> {
    crate::consent::document(doc.0)
}
pub async fn request(
    host: &Arc<Host>,
    guard: &Guard,
    origin: &str,
    path: &str,
    body: Option<Doc>,
    action: &str,
) -> Result<Doc> {
    guard.current(host)?;
    let mut revision = host.workflows.changed.subscribe();
    let mut disconnected = guard.disconnected.clone();
    let work = async {
        let p = host.network.prepare(host, origin, false).await?;
        #[cfg(feature = "fixture")]
        {
            host.hooks.wait_async("workflow:send").await;
            host.hooks.check("workflow:send")?;
        }
        guard.current(host)?;
        let target = chat2local_agent_transport::Target::parse(&format!("{origin}{path}"))
            .map_err(|_| Error::new(400, "Invalid service target."))?;
        let mut attempt = host.network.attempt(&p)?;
        attempt.set_publication_gate(host.network.guard_workflow(
            Arc::downgrade(host),
            p.clone(),
            guard.clone(),
        ));
        let mut headers = Vec::new();
        if let Some((_, id)) = &guard.credential {
            if id.origin != origin {
                return Err(stale());
            }
            headers.push(("authorization".into(), format!("Bearer {}", id.key)));
        }
        let method = if body.is_some() {
            headers.push(("content-type".into(), "application/json".into()));
            "POST"
        } else {
            "GET"
        };
        let response = host
            .network
            .config
            .transport
            .request_once(
                &p.plan,
                &target,
                p.profile,
                chat2local_agent_transport::HttpRequest {
                    method: method.into(),
                    headers,
                    body: body
                        .map(|d| d.raw())
                        .transpose()?
                        .unwrap_or_default()
                        .into_bytes(),
                },
                chat2local_agent_transport::Limits {
                    timeout: std::time::Duration::from_secs(15),
                    body_bytes: 32768,
                },
                &mut attempt,
            )
            .await
            .map_err(|_| Error::new(503, "服务响应未确认，请继续原请求；没有自动改用其他网络。"))?;
        #[cfg(feature = "fixture")]
        {
            let point = format!("workflow:response:{action}");
            host.hooks.wait_async(&point).await;
            host.hooks.check(&point)?;
        }
        #[cfg(not(feature = "fixture"))]
        let _ = action;
        guard.current(host)?;
        let result = Doc::parse(
            std::str::from_utf8(&response.body)
                .map_err(|_| Error::new(503, "Invalid service response."))?,
        )?;
        if !(200..300).contains(&response.status) {
            return Err(Error::new(
                response.status,
                result.s("error").unwrap_or("服务未完成当前步骤。".into()),
            ));
        }
        Ok(result)
    };
    tokio::select! {result=tokio::time::timeout(std::time::Duration::from_secs(16),work)=>result.map_err(|_|Error::new(503,"服务响应未确认，请继续原请求。"))?,_=revision.changed()=>Err(stale()),_=disconnected.changed()=>Err(stale())}
}
