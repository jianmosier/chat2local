//! Owned native terminal jobs. Disk journal work never runs in the process monitor.
use crate::{
    Error, Result,
    bridge::Socket,
    persistence::{Persistence, confirmed},
    runtime::Host,
    tools::{self, Call},
    value,
};
use chat2local_agent_platform::{ControlPipe, GuardedDirectory, TrustedExecutable};
use chat2local_js_value_compat::{Document, Value as J};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    sync::{Notify, oneshot, watch},
};
fn err(message: &str) -> Error {
    Error::new(400, message)
}
fn text(d: &Document, key: &str) -> String {
    value::string(d, value::prop(d, key)).unwrap_or_default()
}
fn final_status(s: &str) -> bool {
    [
        "succeeded",
        "failed",
        "cancelled",
        "timed-out",
        "interrupted",
    ]
    .contains(&s)
}
fn view(record: &Document) -> Result<String> {
    let mut out = value::parse(b"{\"sandboxed\":false}")?;
    for key in [
        "requestId",
        "rootId",
        "status",
        "exitCode",
        "signal",
        "stdout",
        "stderr",
        "truncated",
        "startedAt",
        "endedAt",
        "outcomeKnown",
        "terminationConfirmed",
        "message",
    ] {
        if let Some(id) = value::prop(record, key) {
            let id = out.import(
                value::parse(value::subtree(record, id)?.as_bytes())?,
                usize::MAX,
            )?;
            out.set_property(out.root(), key.encode_utf16().collect(), id)?;
        }
    }
    value::serialized(&out)
}
struct Job {
    record: Mutex<Document>,
    stop: watch::Sender<Option<String>>,
    done: Notify,
    finished: AtomicBool,
}
impl Job {
    fn stop(&self, reason: &str) {
        if !self.finished.load(Ordering::SeqCst) && self.stop.borrow().is_none() {
            self.stop.send_replace(Some(reason.into()));
        }
    }
    fn snapshot(&self) -> Result<Document> {
        self.record.lock().unwrap().try_clone().map_err(Into::into)
    }
}
pub struct Service {
    pub journal: Arc<Persistence>,
    jobs: Mutex<BTreeMap<String, Arc<Job>>>,
    helper: Option<TrustedExecutable>,
    unavailable: AtomicBool,
    supervisors: AtomicUsize,
    progress: AtomicBool,
    pub control_pending: AtomicUsize,
    pub observed_pending: AtomicUsize,
    #[cfg(feature = "fixture")]
    pub stall_ms: AtomicUsize,
    drained: Notify,
}
impl Service {
    pub fn new(
        store: Arc<chat2local_native_store::Store>,
        #[cfg(feature = "fixture")] hooks: Arc<crate::fixture::Hooks>,
    ) -> Arc<Self> {
        let helper = (|| -> Result<TrustedExecutable> {
            let executable = std::env::current_exe()?;
            let directory = executable
                .parent()
                .ok_or_else(|| err("Missing native artifact directory."))?;
            let manifest: Value =
                serde_json::from_slice(&std::fs::read(directory.join("manifest.json"))?)
                    .map_err(|_| err("Invalid native artifact manifest."))?;
            if manifest["fixtureOnly"] != cfg!(feature = "fixture")
                || manifest["terminalRunner"]["fixtureOnly"] != cfg!(feature = "fixture")
                || manifest["fullAgent"] != false
                || manifest["sha256"] != hex::encode(Sha256::digest(std::fs::read(&executable)?))
                || manifest["terminalRunner"]["executable"] != "chat2local-terminal-runner.exe"
            {
                return Err(err("Native terminal provenance unavailable."));
            }
            TrustedExecutable::open(
                &directory.join("chat2local-terminal-runner.exe"),
                manifest["terminalRunner"]["sha256"]
                    .as_str()
                    .ok_or_else(|| err("Missing helper digest."))?,
            )
            .map_err(|_| err("Native terminal helper is not trusted."))
        })();
        Arc::new(Self {
            journal: Persistence::lane(
                store,
                #[cfg(feature = "fixture")]
                hooks,
                "journal",
            ),
            jobs: Mutex::new(BTreeMap::new()),
            helper: helper.ok(),
            unavailable: AtomicBool::new(false),
            supervisors: AtomicUsize::new(0),
            progress: AtomicBool::new(false),
            control_pending: AtomicUsize::new(0),
            observed_pending: AtomicUsize::new(0),
            #[cfg(feature = "fixture")]
            stall_ms: AtomicUsize::new(0),
            drained: Notify::new(),
        })
    }
    pub fn available(&self) -> bool {
        self.helper.is_some() && !self.unavailable.load(Ordering::SeqCst)
    }
    pub fn active(&self) -> usize {
        self.jobs
            .lock()
            .unwrap()
            .values()
            .filter(|j| !final_status(&text(&j.record.lock().unwrap(), "status")))
            .count()
    }
    pub fn supervisors(&self) -> usize {
        self.supervisors.load(Ordering::SeqCst)
    }
    pub fn begin_progress(&self) -> bool {
        !self.progress.swap(true, Ordering::SeqCst)
    }
    pub fn end_progress(&self) {
        self.progress.store(false, Ordering::SeqCst);
        self.drained.notify_one();
    }
    pub fn stop_all(&self) {
        for job in self.jobs.lock().unwrap().values() {
            job.stop("cancelled");
        }
    }
    pub fn stop_roots(&self, connection: &str, roots: &[String]) {
        for job in self.jobs.lock().unwrap().values() {
            let record = job.record.lock().unwrap();
            if text(&record, "connectionId") == connection
                && roots.contains(&text(&record, "rootId"))
            {
                drop(record);
                job.stop("cancelled");
            }
        }
    }
    pub async fn drain(&self) {
        self.stop_all();
        while self.supervisors() != 0 || self.active() != 0 || self.progress.load(Ordering::SeqCst)
        {
            self.drained.notified().await;
        }
        self.journal.drain().await;
    }
    fn write(
        &self,
        _host: &Host,
        operation: &'static str,
        record: Document,
    ) -> Result<oneshot::Receiver<Result<Value>>> {
        let id = text(&record, "requestId");
        let raw = value::serialized(&record)?;
        let nonce = crate::uuid()?;
        #[cfg(feature = "fixture")]
        let hooks = _host.hooks.clone();
        #[cfg(feature = "fixture")]
        let queued = std::time::Instant::now();
        self.journal.submit(move |store| {
            #[cfg(feature = "fixture")]
            hooks.elapsed(&format!("journal:{operation}:queue"), queued);
            #[cfg(feature = "fixture")]
            {
                hooks.wait(if operation == "reserve" {
                    "journal:reserve"
                } else {
                    "journal:save"
                });
                hooks.check(if operation == "reserve" {
                    "journal:reserve"
                } else {
                    "journal:save"
                })?;
            }
            #[cfg(feature = "fixture")]
            let native_started = std::time::Instant::now();
            let result = chat2local_agent_platform::terminal_record_guarded(
                &store.directory().to_string_lossy(),
                operation,
                &id,
                &nonce,
                Some(&raw),
                &|| {
                    store.check_owner().map_err(|_| {
                        chat2local_protocol::Failure::new("EOWNER", "Controller owner changed.")
                    })
                },
            );
            #[cfg(feature = "fixture")]
            hooks.elapsed(&format!("journal:{operation}:native"), native_started);
            let result = result.map_err(|e| err(e.message))?;
            #[cfg(feature = "fixture")]
            if operation == "reserve" {
                hooks.wait("journal:reserved");
                hooks.check("journal:reserved")?;
            }
            Ok(result)
        })
    }
    fn save(self: &Arc<Self>, host: &Arc<Host>, job: &Arc<Job>, running: bool) {
        let received = job
            .snapshot()
            .and_then(|record| self.write(host, "save", record));
        let job = job.clone();
        let service = self.clone();
        tokio::spawn(async move {
            let result = match received {
                Ok(receive) => confirmed(receive, false).await,
                Err(e) => Err(e),
            };
            if result.is_err() {
                let mut record = job.record.lock().unwrap();
                let _ = value::put(
                    &mut record,
                    "message",
                    value::text(
                        "Command state could not be saved. Do not replay; inspect actual effects.",
                    ),
                );
                drop(record);
                if running {
                    job.stop("failed");
                }
            }
            service.drained.notify_one();
        });
    }
    async fn read(&self, host: &Host, id: &str) -> Result<Option<Document>> {
        if let Some(job) = self.jobs.lock().unwrap().get(id) {
            return job.snapshot().map(Some);
        }
        let id = id.to_owned();
        let nonce = crate::uuid()?;
        #[cfg(feature = "fixture")]
        let hooks = host.hooks.clone();
        #[cfg(feature = "fixture")]
        let queued = std::time::Instant::now();
        let receive = self.journal.submit(move |store| {
            #[cfg(feature = "fixture")]
            hooks.elapsed("journal:read:queue", queued);
            #[cfg(feature = "fixture")]
            let native_started = std::time::Instant::now();
            let result = chat2local_agent_platform::terminal_record_guarded(
                &store.directory().to_string_lossy(),
                "read",
                &id,
                &nonce,
                None,
                &|| {
                    store.check_owner().map_err(|_| {
                        chat2local_protocol::Failure::new("EOWNER", "Controller owner changed.")
                    })
                },
            );
            #[cfg(feature = "fixture")]
            hooks.elapsed("journal:read:native", native_started);
            result.map_err(|e| err(e.message))
        })?;
        let result = journal_confirmed(host, "read", receive).await?;
        if result["kind"] == "missing" {
            Ok(None)
        } else {
            let raw = result["recordJson"]
                .as_str()
                .ok_or_else(|| err("Invalid terminal journal receipt."))?;
            value::parse(raw.as_bytes()).map(Some)
        }
    }
}
async fn journal_confirmed(
    _host: &Host,
    operation: &str,
    receive: oneshot::Receiver<Result<Value>>,
) -> Result<Value> {
    // Match RustTerminalRecords' existing per-call budget, including queueing,
    // locking, DPAPI, flushes and receipt validation. The recovery lane's one
    // second acknowledgement bound is not a terminal storage deadline.
    #[cfg(feature = "fixture")]
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(15), confirmed(receive, false))
        .await
        .unwrap_or_else(|_| {
            Err(Error::new(
                503,
                format!("EPERSISTENCE: Terminal journal {operation} exceeded its 15-second confirmation budget; ownership is retained. Do not replay."),
            ))
        });
    #[cfg(feature = "fixture")]
    _host.hooks.elapsed(
        &format!(
            "journal:{operation}:confirmed-{}",
            if result.is_ok() { "ok" } else { "error" }
        ),
        started,
    );
    result
}
fn owns(record: &Document, call: &Call) -> Result<bool> {
    let access = call
        .access
        .as_ref()
        .ok_or_else(|| err("Scoped terminal authority required."))?;
    Ok(text(record, "rootId") == text(&call.args, "rootId")
        && ["connectionId", "deviceId", "resource"]
            .iter()
            .all(|key| text(record, key) == text(access, key)))
}
fn hash_input(call: &Call, timeout: u64) -> Result<String> {
    let access = call
        .access
        .as_ref()
        .ok_or_else(|| err("Scoped terminal authority required."))?;
    let mut out = value::parse(b"[]")?;
    for (key, fallback) in [("command", ""), ("cwd", ".")] {
        let doc = if value::truthy(&call.args, value::prop(&call.args, key)) {
            value::parse(
                value::subtree(&call.args, value::prop(&call.args, key).unwrap())?.as_bytes(),
            )?
        } else {
            value::parse(json!(fallback).to_string().as_bytes())?
        };
        let id = out.import(doc, usize::MAX)?;
        out.push(out.root(), id)?;
    }
    for v in [
        J::Number(timeout as f64),
        value::text("powershell"),
        value::text(&text(&call.args, "rootId")),
        value::text(&text(access, "connectionId")),
        value::text(&text(access, "resource")),
        value::text(&text(access, "deviceId")),
    ] {
        let id = out.add(v, usize::MAX)?;
        out.push(out.root(), id)?;
    }
    Ok(hex::encode(Sha256::digest(
        value::serialized(&out)?.as_bytes(),
    )))
}
pub async fn execute(
    host: &Arc<Host>,
    call: &Call,
    socket: &Arc<Socket>,
    fingerprint: &str,
    request: chat2local_protocol::Request,
) -> Result<String> {
    let service = &host.terminal;
    let id = text(&call.args, "requestId");
    let hash = if call.tool == "terminal_execute" {
        let shell = text(&call.args, "shell");
        if !["", "auto", "powershell"].contains(&shell.as_str()) {
            return Err(err("Requested shell unavailable on this native platform."));
        }
        Some(hash_input(
            call,
            value::number(&call.args, value::prop(&call.args, "timeoutMs")).unwrap_or(120000.0)
                as u64,
        )?)
    } else {
        None
    };
    if let Some(mut previous) = service.read(host, &id).await? {
        if !owns(&previous, call)?
            || hash
                .as_ref()
                .is_some_and(|h| text(&previous, "inputHash") != *h)
        {
            return Err(err(
                "requestId belongs to another command or owner; nothing executed.",
            ));
        }
        let job = service.jobs.lock().unwrap().get(&id).cloned();
        if let Some(job) = job {
            if call.tool == "terminal_cancel" && !job.finished.load(Ordering::SeqCst) {
                job.stop("cancelled");
                let _ = tokio::time::timeout(Duration::from_secs(4), async {
                    while !job.finished.load(Ordering::SeqCst) {
                        job.done.notified().await;
                    }
                })
                .await;
            }
            return view(&job.record.lock().unwrap());
        }
        if !final_status(&text(&previous, "status")) {
            value::put(&mut previous, "status", value::text("interrupted"))?;
            value::put(&mut previous, "outcomeKnown", J::Bool(false))?;
            value::put(
                &mut previous,
                "message",
                value::text(
                    "The agent restarted. Do not replay this command; inspect its effects first.",
                ),
            )?;
        }
        return view(&previous);
    }
    if call.tool != "terminal_execute" {
        return Err(err(
            "Command does not belong to this connection, device and root.",
        ));
    }
    if !service.available() || service.active() >= 2 {
        return Err(err(
            "Native terminal unavailable or two jobs already active.",
        ));
    }
    {
        let mut jobs = service.jobs.lock().unwrap();
        if jobs.len() >= 128 {
            let victim = jobs
                .iter()
                .find(|(_, j)| j.finished.load(Ordering::SeqCst))
                .map(|(id, _)| id.clone())
                .ok_or_else(|| err("Terminal capacity reached."))?;
            jobs.remove(&victim);
        }
    }
    let root = request.authority.root.path;
    let cwd = value::string(&call.args, value::prop(&call.args, "cwd"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| ".".into());
    let directory = host.store.directory().to_string_lossy().into_owned();
    let guarded = tokio::task::spawn_blocking(move || {
        GuardedDirectory::open(&root, &cwd, &directory).map_err(|e| err(e.message))
    })
    .await
    .map_err(|_| err("Directory guard failed."))??;
    let access = call.access.as_ref().unwrap();
    let record=value::parse(json!({"requestId":id,"rootId":text(&call.args,"rootId"),"connectionId":text(access,"connectionId"),"resource":text(access,"resource"),"deviceId":text(access,"deviceId"),"inputHash":hash.unwrap(),"status":"starting","stdout":"","stderr":"","truncated":false,"exitCode":null,"signal":null,"startedAt":tools::iso_now(),"outcomeKnown":false}).to_string().as_bytes())?;
    socket.with_current(host, call, fingerprint, |_| Ok(()))?;
    let reserved = journal_confirmed(
        host,
        "reserve",
        service.write(host, "reserve", record.try_clone()?)?,
    )
    .await?;
    if reserved["kind"] != "created" {
        return Err(err(
            "Terminal reservation did not grant a new launch right; query status only.",
        ));
    }
    socket.with_current(host, call, fingerprint, |_| {
        host.store
            .check_owner()
            .map_err(|_| err("Controller owner changed."))
    })?;
    let (stop, stop_receiver) = watch::channel(None);
    let job = Arc::new(Job {
        record: Mutex::new(record),
        stop,
        done: Notify::new(),
        finished: AtomicBool::new(false),
    });
    service.jobs.lock().unwrap().insert(id, job.clone());
    let (started, receive) = oneshot::channel();
    let captured = call.copy()?;
    let expected = fingerprint.to_owned();
    let owner = host.clone();
    let socket = socket.clone();
    let service = service.clone();
    service.supervisors.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        let result = supervise(
            &owner,
            &service,
            &job,
            &captured,
            &socket,
            &expected,
            PreparedLaunch {
                guarded,
                started,
                stop: stop_receiver,
            },
        )
        .await;
        if result.is_err() {
            unknown(&owner, &service, &job);
        }
        service.supervisors.fetch_sub(1, Ordering::SeqCst);
        service.drained.notify_one();
    });
    receive
        .await
        .map_err(|_| err("Terminal start is not confirmed; query only, never replay."))?
}
fn completion(
    service: &Arc<Service>,
    tasks: &mut tokio::task::JoinSet<Result<()>>,
    submission: chat2local_agent_platform::Submission,
) {
    service.control_pending.fetch_add(1, Ordering::SeqCst);
    if submission.pending() {
        service.observed_pending.fetch_add(1, Ordering::SeqCst);
    }
    let service = service.clone();
    tasks.spawn_blocking(move || {
        let result = submission.complete().map_err(|e| err(e.message));
        service.control_pending.fetch_sub(1, Ordering::SeqCst);
        service.drained.notify_one();
        result
    });
}
fn unknown(host: &Host, service: &Service, job: &Job) {
    service.unavailable.store(true, Ordering::SeqCst);
    host.lock_state().terminal_available = false;
    let mut record = job.record.lock().unwrap();
    let _ = value::put(&mut record, "status", value::text("stopping"));
    let _ = value::put(&mut record, "outcomeKnown", J::Bool(false));
    let _ = value::put(&mut record, "terminationConfirmed", J::Bool(false));
    let _ = value::put(
        &mut record,
        "message",
        value::text(
            "Command cleanup is not confirmed. Capacity and ownership remain retained; do not replay.",
        ),
    );
    job.done.notify_one();
}
fn environment(command: &mut tokio::process::Command) {
    command.env_clear();
    for key in [
        "PATH",
        "Path",
        "PATHEXT",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LC_ALL",
        "NUMBER_OF_PROCESSORS",
    ] {
        if let Some(v) = std::env::var_os(key) {
            command.env(key, v);
        }
    }
    command.env("NO_COLOR", "1");
}
fn exact(frame: &Value, keys: &[&str]) -> bool {
    frame
        .as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
}
struct Decoder(Vec<u8>);
impl Decoder {
    fn push(&mut self, bytes: &[u8], finish: bool) -> String {
        self.0.extend_from_slice(bytes);
        let mut out = String::new();
        loop {
            match std::str::from_utf8(&self.0) {
                Ok(s) => {
                    out.push_str(s);
                    self.0.clear();
                    break;
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    out.push_str(std::str::from_utf8(&self.0[..valid]).unwrap());
                    self.0.drain(..valid);
                    if let Some(len) = e.error_len() {
                        out.push('\u{fffd}');
                        self.0.drain(..len);
                    } else {
                        if finish && !self.0.is_empty() {
                            out.push('\u{fffd}');
                            self.0.clear();
                        }
                        break;
                    }
                }
            }
        }
        out
    }
}
struct PreparedLaunch {
    guarded: GuardedDirectory,
    started: oneshot::Sender<Result<String>>,
    stop: watch::Receiver<Option<String>>,
}
async fn supervise(
    host: &Arc<Host>,
    service: &Arc<Service>,
    job: &Arc<Job>,
    call: &Call,
    socket: &Arc<Socket>,
    fingerprint: &str,
    launch: PreparedLaunch,
) -> Result<()> {
    let PreparedLaunch {
        guarded,
        started,
        mut stop,
    } = launch;
    let mut started = Some(started);
    let mut binding = json!({"v":1,"session":crate::uuid()?,"requestId":text(&call.args,"requestId"),"inputHash":text(&job.record.lock().unwrap(),"inputHash")});
    #[cfg(feature = "fixture")]
    let stall = service.stall_ms.swap(0, Ordering::SeqCst);
    #[cfg(not(feature = "fixture"))]
    let stall = 0;
    let (pipe, input) =
        ControlPipe::with_capacity(&crate::random(32)?, if stall > 0 { 256 } else { 65536 })
            .map_err(|e| err(e.message))?;
    let mut command = tokio::process::Command::new(&service.helper.as_ref().unwrap().path);
    #[cfg(feature = "fixture")]
    if stall > 0 {
        command.args(["--fixture-control-stall-ms", &stall.to_string()]);
    }
    environment(&mut command);
    command.kill_on_drop(true);
    command
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    #[cfg(feature = "fixture")]
    host.hooks.wait_async("terminal:spawn").await;
    let mut child = command.spawn()?;
    drop(command);

    let timeout =
        value::number(&call.args, value::prop(&call.args, "timeoutMs")).unwrap_or(120000.0) as u64;
    let mut prepare = binding.clone();
    prepare["kind"] = json!("prepare");
    prepare["command"] =
        json!(value::execution_string(&call.args, value::prop(&call.args, "command")).unwrap());
    prepare["cwd"] = json!(guarded.path);
    prepare["timeoutMs"] = json!(timeout);
    let mut protocol_failure = false;
    let mut completions = tokio::task::JoinSet::new();
    match pipe.submit(format!("{prepare}\n").into_bytes()) {
        Ok(submitted) => completion(service, &mut completions, submitted),
        Err(_) => {
            protocol_failure = true;
        }
    }
    let mut stdout = BufReader::new(
        child
            .stdout
            .take()
            .ok_or_else(|| err("Missing helper output."))?,
    );
    let mut line = Vec::new();
    let mut phase = "prepare";
    let mut run_sent = false;
    let mut bytes = 0usize;
    let mut decoders = [Decoder(Vec::new()), Decoder(Vec::new())];
    let mut exit = None;
    let mut stopping = false;
    let mut deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut watch = tokio::time::interval(Duration::from_millis(200));
    let monitored:Result<()>=async {
    while !protocol_failure {
        let mut limited = (&mut stdout).take((256 * 1024 + 1 - line.len()) as u64);
        tokio::select! {
         result=completions.join_next(),if !completions.is_empty()=>{if result.is_none_or(|r|r.is_err()||r.is_ok_and(|v|v.is_err())){protocol_failure=true;break;}},
         _=watch.tick()=>{if host.faulted()||host.closing.load(Ordering::SeqCst)||tools::prepare(&host.lock_state(),call).is_err(){job.stop("cancelled");}},
         _=stop.changed(),if !stopping=>{if stop.borrow().is_some(){stopping=true;deadline=tokio::time::Instant::now()+Duration::from_secs(4);{let mut r=job.record.lock().unwrap();value::put(&mut r,"status",value::text("stopping"))?;}binding["kind"]=json!("cancel");match pipe.submit(format!("{binding}\n").into_bytes()){Ok(submitted)=>completion(service,&mut completions,submitted),Err(_)=>{protocol_failure=true;break;}}}},
         _=tokio::time::sleep_until(deadline)=>{protocol_failure=true;break;},
         n=limited.read_until(b'\n',&mut line)=>{
          let n=match n{Ok(n)=>n,Err(_)=>{protocol_failure=true;break;}};
          if n==0{break;}
          if line.len()>256*1024||line.last()!=Some(&b'\n'){protocol_failure=true;break;}
          let frame:Value=match serde_json::from_slice(&line){Ok(v)=>v,Err(_)=>{protocol_failure=true;break;}};line.clear();
          if ["v","session","requestId","inputHash"].iter().any(|k|frame[*k]!=binding[*k]){protocol_failure=true;break;}
          let base=["v","session","requestId","inputHash","kind"];
          match frame["kind"].as_str(){
           Some("ready")if phase=="prepare"&&exact(&frame,&base)&&!stopping=>{
            #[cfg(feature="fixture")]host.hooks.wait_async("terminal:ready").await;
            let mut run=binding.clone();run["kind"]=json!("run");let data=format!("{run}\n").into_bytes();
            let submitted=socket.with_current(host,call,fingerprint,|_|{host.store.check_owner().map_err(|_|err("Controller owner changed."))?;let submitted=pipe.submit(data).map_err(|e|err(e.message))?;run_sent=true;Ok(submitted)});
            match submitted{Ok(submitted)=>{phase="run";completion(service,&mut completions,submitted);},Err(_)=>{job.stop("cancelled");continue;}}
           },
           Some("started")if phase=="run"&&exact(&frame,&[&base[..],&["pid"]].concat())&&frame["pid"].as_u64().is_some_and(|n|n>0)=>{
            phase="running";
            if !stopping{deadline=tokio::time::Instant::now()+Duration::from_millis(timeout+5500);}
            {let mut r=job.record.lock().unwrap();value::put(&mut r,"status",value::text(if stopping{"stopping"}else{"running"}))?;}
            if let Some(sender)=started.take(){let _=sender.send(view(&job.record.lock().unwrap()));}
            service.save(host,job,true);
           },
           Some("output")if phase=="running"&&exact(&frame,&[&base[..],&["stream","data","truncated"]].concat())=>{
            let Some(stream)=frame["stream"].as_str().filter(|s|["stdout","stderr"].contains(s))else{protocol_failure=true;break;};let Some(data)=frame["data"].as_str().filter(|s|s.len()<=8192&&s.len()%2==0&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)))else{protocol_failure=true;break;};let Some(truncated)=frame["truncated"].as_bool()else{protocol_failure=true;break;};let data=hex::decode(data).map_err(|_|err("Invalid helper output."))?;bytes+=data.len();if bytes>65536{protocol_failure=true;break;}let decoded=decoders[usize::from(stream=="stderr")].push(&data,false);let mut r=job.record.lock().unwrap();let content=text(&r,stream)+&decoded;value::put(&mut r,stream,value::text(&content))?;if truncated{value::put(&mut r,"truncated",J::Bool(true))?;}
           },
           Some("exit")if exit.is_none()&&exact(&frame,&[&base[..],&["exitCode","reason","terminationConfirmed","truncated","code"]].concat())=>{
            let valid=(frame["exitCode"].is_null()||frame["exitCode"].as_u64().is_some_and(|n|n<=u32::MAX as u64))&&frame["terminationConfirmed"].is_boolean()&&frame["truncated"].is_boolean()&&["exited","failed","cancelled","timed-out","control-lost"].contains(&frame["reason"].as_str().unwrap_or(""))&&(phase=="running"||frame["reason"]!="exited")&&(frame["code"].is_null()||["EWIN32","EATTRIBUTES","EPIPE","EJOB","ECOMMAND","ESPAWN","EASSIGN","ERESUME","EOUTPUT","EACCESS","EPROTOCOL","ENOTSUP"].contains(&frame["code"].as_str().unwrap_or("")));
            if !valid{protocol_failure=true;break;}exit=Some(frame);phase="exit";
           },_=>{protocol_failure=true;break;}
          }
         }
        }
    }
    Ok(())}.await;
    if monitored.is_err() {
        protocol_failure = true;
    }
    if protocol_failure {
        pipe.cancel_pending();
        let _ = child.start_kill();
    }
    let closed = tokio::time::timeout(Duration::from_secs(4), child.wait()).await;
    let mut helper_closed = closed.as_ref().is_ok_and(|r| r.is_ok());
    if !helper_closed {
        pipe.cancel_pending();
        let _ = child.start_kill();
        helper_closed = child.wait().await.is_ok();
        protocol_failure = true;
    }
    if !helper_closed {
        unknown(host, service, job);
        if let Some(sender) = started.take() {
            let _ = sender.send(view(&job.record.lock().unwrap()));
        }
        // A wait error is not process completion. Keep the actual Child, pipe,
        // guarded cwd and pending I/O owned by this supervisor until a wait
        // proves closure; unknown flags alone cannot release host ownership.
        loop {
            pipe.cancel_pending();
            let _ = child.start_kill();
            tokio::time::sleep(Duration::from_secs(1)).await;
            if child.wait().await.is_ok() {
                break;
            }
        }
        helper_closed = true;
    }
    while let Some(completed) = completions.join_next().await {
        if completed.map_or(true, |r| r.is_err()) {
            protocol_failure = true;
        }
    }
    let confirmed = !protocol_failure
        && line.is_empty()
        && closed
            .as_ref()
            .is_ok_and(|r| r.as_ref().is_ok_and(|s| s.success()))
        && exit
            .as_ref()
            .is_some_and(|e| e["terminationConfirmed"] == true);
    if !helper_closed || !confirmed && run_sent {
        unknown(host, service, job);
        if let Some(sender) = started.take() {
            let _ = sender.send(view(&job.record.lock().unwrap()));
        }
        return Ok(());
    }
    let end = exit.unwrap_or_else(|| json!({"reason":"failed","exitCode":null,"truncated":false}));
    let requested = job.stop.borrow().clone();
    let status = requested
        .as_deref()
        .unwrap_or_else(|| match end["reason"].as_str() {
            Some("exited") if end["exitCode"] == 0 => "succeeded",
            Some("timed-out") => "timed-out",
            Some("cancelled" | "control-lost") => "cancelled",
            _ => "failed",
        });
    {
        let mut r = job.record.lock().unwrap();
        for (i, key) in ["stdout", "stderr"].iter().enumerate() {
            let content = text(&r, key) + &decoders[i].push(&[], true);
            value::put(&mut r, key, value::text(&content))?;
        }
        value::put(&mut r, "status", value::text(status))?;
        value::put(&mut r, "endedAt", value::text(&tools::iso_now()))?;
        value::put(&mut r, "outcomeKnown", J::Bool(true))?;
        value::put(&mut r, "terminationConfirmed", J::Bool(true))?;
        value::put(
            &mut r,
            "exitCode",
            end["exitCode"].as_f64().map(J::Number).unwrap_or(J::Null),
        )?;
        if end["truncated"] == true {
            value::put(&mut r, "truncated", J::Bool(true))?;
        }
    }
    job.finished.store(true, Ordering::SeqCst);
    job.done.notify_one();
    if let Some(sender) = started.take() {
        let _ = sender.send(view(&job.record.lock().unwrap()));
    }
    service.save(host, job, false);
    drop(guarded);
    Ok(())
}
