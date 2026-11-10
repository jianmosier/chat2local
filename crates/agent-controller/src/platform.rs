//! Host-owned Windows shell work; human waits never occupy the ordinary FIFO.
use crate::{Error, Reply, Result, runtime::Host, value};
use chat2local_agent_platform as os;
use chat2local_js_value_compat::{Document, Value as J};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    sync::{Notify, oneshot, watch},
};
const PREFIX: &str = "$ErrorActionPreference='Stop';[Console]::InputEncoding=New-Object Text.UTF8Encoding($false);[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false);$c=([Console]::In.ReadLine()|ConvertFrom-Json);";
const PICKER: &str = "Add-Type -AssemblyName System.Windows.Forms;$o=New-Object System.Windows.Forms.Form;$d=New-Object System.Windows.Forms.FolderBrowserDialog;try{$o.Text='Chat2Local - Select folder';$o.TopMost=$true;$o.ShowInTaskbar=$false;$o.StartPosition='CenterScreen';$o.Width=1;$o.Height=1;$o.Opacity=0;$o.Show();$o.Activate();$d.Description='Chat2Local: select a folder. Sharing requires confirmation on the next page.';$d.ShowNewFolderButton=$false;$p=$null;if($d.ShowDialog($o) -eq [System.Windows.Forms.DialogResult]::OK){$p=$d.SelectedPath};@{path=$p}|ConvertTo-Json -Compress}finally{$d.Dispose();$o.Close();$o.Dispose()}";
const BROWSER: &str = "Start-Process -FilePath $c.url;@{dispatched=$true}|ConvertTo-Json -Compress";
const STARTUP: &str = "$s=New-Object -ComObject WScript.Shell;if($c.previous){$old=$s.CreateShortcut($c.previous);if($old.Description -ne 'Chat2Local managed startup'){throw 'Unowned shortcut'}};if($c.enabled){$l=$s.CreateShortcut($c.temporary);$l.TargetPath=$c.target;$l.Arguments=$c.arguments;$l.WorkingDirectory=$c.working;$l.WindowStyle=7;$l.Description='Chat2Local managed startup';$l.Save();$f=[IO.File]::Open($c.temporary,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$v=$s.CreateShortcut($c.temporary);if($v.TargetPath -ne $c.target -or $v.Arguments -ne $c.arguments -or $v.WorkingDirectory -ne $c.working -or $v.Description -ne 'Chat2Local managed startup'){throw 'Unexpected produced shortcut'};$sha=[Security.Cryptography.SHA256]::Create();try{$digest=([BitConverter]::ToString($sha.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}finally{$f.Dispose()}};@{prepared=$true;sha256=$digest}|ConvertTo-Json -Compress";
#[cfg(feature = "fixture")]
const SYNTHETIC: &str = "if($c.delayMs -gt 0){Start-Sleep -Milliseconds $c.delayMs};switch($c.mode){'selected'{@{path=$c.path}|ConvertTo-Json -Compress}'cancel'{@{path=$null}|ConvertTo-Json -Compress}'capture'{@{dispatched=$true;captured=$true}|ConvertTo-Json -Compress}'invalid'{[Console]::Out.Write('invalid')}'overflow'{[Console]::Out.Write(('x'*40000))}'nonzero'{exit 7}'stall'{Start-Sleep -Seconds 180}default{exit 9}}";
fn failed() -> Error {
    Error::new(
        503,
        "Windows platform helper failed; no successful action was inferred.",
    )
}

#[cfg(test)]
mod consent_gate_tests {
    use super::*;
    #[test]
    fn selection_and_disconnect_remain_locked_until_publication_closure_returns() {
        let service = Service::new(
            #[cfg(feature = "fixture")]
            Default::default(),
        )
        .unwrap();
        let revision = service.selection_revision();
        let (disconnect, read) = watch::channel(false);
        let guard = read.borrow();
        let (started, starting) = std::sync::mpsc::channel();
        let other = service.clone();
        let cancellation = std::thread::spawn(move || {
            starting.recv().unwrap();
            other.cancel_picker();
        });
        service.with_selection(Some(revision), |current| {
            assert!(current);
            assert!(!*guard);
            // Exact production gate holds the cancellation mutex at syscall admission.
            assert!(service.state.try_lock().is_err());
            started.send(()).unwrap();
            assert_eq!(service.selection.borrow().to_owned(), revision);
        });
        cancellation.join().unwrap();
        assert_ne!(service.selection_revision(), revision);
        let (started, starting) = std::sync::mpsc::channel();
        let (done, finished) = std::sync::mpsc::channel();
        let disconnected = std::thread::spawn(move || {
            started.send(()).unwrap();
            disconnect.send_replace(true);
            done.send(()).unwrap();
        });
        starting.recv().unwrap();
        assert!(finished.try_recv().is_err());
        assert!(!*guard);
        drop(guard);
        finished.recv_timeout(Duration::from_secs(1)).unwrap();
        disconnected.join().unwrap();
        assert!(*read.borrow());
    }
}
fn stale() -> Error {
    Error::new(
        409,
        "Platform operation was cancelled or its authority changed.",
    )
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mode {
    pub mode: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub delay_ms: u64,
    pub timeout_ms: Option<u64>,
}
impl Mode {
    fn normal() -> Self {
        Self {
            mode: "normal".into(),
            path: String::new(),
            delay_ms: 0,
            timeout_ms: None,
        }
    }
    #[cfg(feature = "fixture")]
    fn validate(&self, picker: bool) -> Result<()> {
        let allowed = if picker {
            &[
                "normal", "selected", "cancel", "invalid", "overflow", "nonzero", "stall",
            ][..]
        } else {
            &["capture", "nonzero", "stall"][..]
        };
        if !allowed.contains(&self.mode.as_str())
            || self.delay_ms > 10000
            || self.path.encode_utf16().count() > 2048
            || self
                .timeout_ms
                .is_some_and(|n| n < 100 || n > if picker { 120000 } else { 10000 })
        {
            return Err(Error::new(400, "Invalid bounded platform fixture."));
        }
        Ok(())
    }
}
#[cfg(feature = "fixture")]
#[derive(Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub picker: Option<Mode>,
    pub browser: Option<Mode>,
    pub startup: Option<Startup>,
}
#[cfg(feature = "fixture")]
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Startup {
    pub directory: PathBuf,
}
struct State {
    closed: bool,
    picker: bool,
    revision: u64,
    picker_mode: Mode,
    browser_mode: Mode,
}
pub struct Service {
    state: Mutex<State>,
    cancel: watch::Sender<bool>,
    selection: watch::Sender<u64>,
    pending: AtomicUsize,
    drained: Notify,
    pub browse: Arc<tokio::sync::Semaphore>,
    browser_slots: Arc<tokio::sync::Semaphore>,
    starts: AtomicUsize,
    active: AtomicUsize,
    pids: Mutex<Vec<u32>>,
    #[cfg(feature = "fixture")]
    startup: Option<Startup>,
}
struct Owned(Arc<Service>);
struct Invocation {
    workflow: Option<crate::workflow::Guard>,
    epoch: u64,
    selection: Option<u64>,
    disconnected: watch::Receiver<bool>,
    script: &'static str,
    input: Value,
    duration: Duration,
    sta: bool,
    browser: bool,
}
fn script(mode: &Mode, ordinary: &'static str) -> &'static str {
    #[cfg(feature = "fixture")]
    if mode.mode != "normal" {
        return SYNTHETIC;
    }
    let _ = mode;
    ordinary
}
impl Drop for Owned {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::SeqCst);
        self.0.drained.notify_one();
    }
}
impl Service {
    pub fn new(#[cfg(feature = "fixture")] config: Config) -> Result<Arc<Self>> {
        #[cfg(feature = "fixture")]
        {
            if let Some(m) = &config.picker {
                m.validate(true)?;
            }
            if let Some(m) = &config.browser {
                m.validate(false)?;
            }
            if let Some(s) = &config.startup {
                let d = os::ShellDirectory::open(&s.directory).map_err(|_| failed())?;
                let startup = os::shell_folder(7).map_err(|_| failed())?;
                if os::within(&startup, &d.path)
                    || os::within(&d.path, &startup)
                    || std::fs::read(d.path.join(".chat2local-startup-fixture"))?
                        != b"synthetic-startup-only\n"
                {
                    return Err(Error::new(
                        400,
                        "Marked temporary startup fixture required.",
                    ));
                }
            }
        }
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                closed: false,
                picker: false,
                revision: 0,
                picker_mode: {
                    #[cfg(feature = "fixture")]
                    {
                        config.picker.unwrap_or_else(Mode::normal)
                    }
                    #[cfg(not(feature = "fixture"))]
                    {
                        Mode::normal()
                    }
                },
                browser_mode: {
                    #[cfg(feature = "fixture")]
                    {
                        config.browser.unwrap_or_else(Mode::normal)
                    }
                    #[cfg(not(feature = "fixture"))]
                    {
                        Mode::normal()
                    }
                },
            }),
            cancel: watch::channel(false).0,
            selection: watch::channel(0).0,
            pending: AtomicUsize::new(0),
            drained: Notify::new(),
            browse: Arc::new(tokio::sync::Semaphore::new(2)),
            browser_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            starts: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            pids: Mutex::new(Vec::new()),
            #[cfg(feature = "fixture")]
            startup: config.startup,
        }))
    }
    fn own(self: &Arc<Self>) -> Owned {
        self.pending.fetch_add(1, Ordering::SeqCst);
        Owned(self.clone())
    }
    pub fn cancel_picker(&self) {
        let mut s = self.state.lock().unwrap();
        s.revision += 1;
        self.selection.send_replace(s.revision);
    }
    pub fn selection_revision(&self) -> u64 {
        self.state.lock().unwrap().revision
    }
    pub(crate) fn with_selection<T>(
        &self,
        expected: Option<u64>,
        work: impl FnOnce(bool) -> T,
    ) -> T {
        match expected {
            Some(expected) => {
                let state = self.state.lock().unwrap();
                work(!state.closed && state.revision == expected)
            }
            None => work(true),
        }
    }
    pub fn close(&self) {
        let mut s = self.state.lock().unwrap();
        s.closed = true;
        s.revision += 1;
        self.selection.send_replace(s.revision);
        self.cancel.send_replace(true);
    }
    pub fn picker_active(&self) -> bool {
        self.state.lock().unwrap().picker
    }
    #[cfg(feature = "fixture")]
    pub fn startup_available(&self) -> bool {
        self.startup.is_some()
    }
    pub async fn drain(&self) {
        while self.pending.load(Ordering::SeqCst) != 0 {
            self.drained.notified().await;
        }
    }
    fn gate<T>(
        &self,
        host: &Host,
        epoch: u64,
        selection: Option<u64>,
        work: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.gate_workflow(host, epoch, selection, None, work)
    }
    fn gate_workflow<T>(
        &self,
        host: &Host,
        epoch: u64,
        selection: Option<u64>,
        workflow: Option<&crate::workflow::Guard>,
        work: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let _core = host.core.lock().unwrap_or_else(|e| e.into_inner());
        let state = host.lock_state();
        let disconnected = workflow.map(|g| g.disconnected.borrow());
        let workflow_state = workflow.map(|_| host.workflows.inner.lock().unwrap());
        if let Some(g) = workflow {
            if disconnected.as_ref().is_some_and(|v| **v) {
                return Err(stale());
            }
            g.check(host, &state, workflow_state.as_ref().unwrap())?;
        }
        let shell = self.state.lock().unwrap();
        if host.faulted()
            || host.closing.load(Ordering::SeqCst)
            || !host.active.load(Ordering::SeqCst)
            || selection.is_none() && state.epoch != epoch
            || selection.is_some()
                && value::boolean(&state.config, value::prop(&state.config, "paused")) == Some(true)
            || shell.closed
            || selection.is_some_and(|r| r != shell.revision)
        {
            return Err(stale());
        }
        host.store.check_owner()?;
        work()
    }
    #[cfg(feature = "fixture")]
    pub fn configure(&self, v: &Value) -> Result<Value> {
        let config: Config = serde_json::from_value(v.clone())
            .map_err(|_| Error::new(400, "Invalid platform configuration."))?;
        if config.startup.is_some() {
            return Err(Error::new(400, "Startup fixture cannot change."));
        }
        if let Some(m) = &config.picker {
            m.validate(true)?;
        }
        if let Some(m) = &config.browser {
            m.validate(false)?;
        }
        let mut s = self.state.lock().unwrap();
        if let Some(m) = config.picker {
            s.picker_mode = m;
        }
        if let Some(m) = config.browser {
            s.browser_mode = m;
        }
        Ok(json!({"configured":true}))
    }
    #[cfg(feature = "fixture")]
    pub fn inspect(&self) -> Value {
        json!({"fixtureStartupAdapterAvailable":self.startup_available(),"pickerActive":self.picker_active(),"browseActive":2-self.browse.available_permits(),"platformPending":self.pending.load(Ordering::SeqCst),"helperStarts":self.starts.load(Ordering::SeqCst),"helperActive":self.active.load(Ordering::SeqCst),"helperPids":*self.pids.lock().unwrap()})
    }
    #[cfg(feature = "fixture")]
    pub fn fixture_browser_allowed(&self) -> bool {
        self.state.lock().unwrap().browser_mode.mode != "normal"
    }
    async fn helper(self: &Arc<Self>, host: &Arc<Host>, invocation: Invocation) -> Result<Value> {
        let Invocation {
            workflow,
            epoch,
            selection,
            mut disconnected,
            script,
            input,
            duration,
            sta,
            browser,
        } = invocation;
        let mut closed = self.cancel.subscribe();
        let mut workflow_revision = host.workflows.changed.subscribe();
        let mut selected = self.selection.subscribe();
        #[cfg(feature = "fixture")]
        host.hooks.wait_async("platform:spawn").await;
        if *disconnected.borrow() {
            return Err(stale());
        }
        let trusted = os::system_powershell().map_err(|_| failed())?;
        let (pipe, read) = os::ControlPipe::pair(&crate::random(32)?).map_err(|_| failed())?;
        let mut command = tokio::process::Command::new(&trusted.path);
        command.env_clear();
        // Shell COM expands this OS variable even under a minimal environment.
        // Derive it from the held system image, never from caller/PATH input.
        command.env(
            "SystemDrive",
            trusted
                .path
                .components()
                .next()
                .ok_or_else(failed)?
                .as_os_str(),
        );
        command.current_dir(host.store.directory());
        for key in [
            "SystemRoot",
            "WINDIR",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
        ] {
            if let Some(v) = std::env::var_os(key) {
                command.env(key, v);
            }
        }
        let full = format!("{PREFIX}{script}");
        command.args(["-NoLogo", "-NoProfile"]);
        if !sta {
            command.arg("-NonInteractive");
        }
        if sta {
            command.arg("-STA");
        }
        command
            .args(["-Command", &full])
            .stdin(Stdio::from(read))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let mut child = self.gate_workflow(host, epoch, selection, workflow.as_ref(), || {
            command.spawn().map_err(|_| failed())
        })?;
        drop(command);
        let pid = child.id().ok_or_else(failed)?;
        self.starts.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        self.pids.lock().unwrap().push(pid);
        let stdout = child.stdout.take().unwrap();
        let mut reader = tokio::spawn(async move {
            let mut b = Vec::new();
            stdout.take(32769).read_to_end(&mut b).await.map(|_| b)
        });
        let submitted = if *disconnected.borrow() {
            Err(stale())
        } else {
            self.gate_workflow(host, epoch, selection, workflow.as_ref(), || {
                pipe.submit(format!("{input}\n").into_bytes())
                    .map_err(|_| failed())
            })
        };
        let was_submitted = submitted.is_ok();
        let writer = submitted.map(|s| tokio::task::spawn_blocking(move || s.complete()));
        #[cfg(feature = "fixture")]
        if browser && was_submitted && workflow.is_some() {
            host.hooks.wait_async("workflow:browser-submitted").await;
        }
        let deadline = tokio::time::Instant::now() + duration;
        let mut output = None;
        let mut status = None;
        let mut success = writer.is_ok();
        if success {
            success = tokio::select! {biased;_=closed.changed()=>false,_=disconnected.changed()=>false,_=workflow_revision.changed(),if workflow.is_some()=>false,_=selected.changed(),if selection.is_some()=>false,_=tokio::time::sleep_until(deadline)=>false,r=&mut reader=>{output=Some(r);true},s=child.wait()=>{status=Some(s);true}};
        }
        success &= output.as_ref().is_none_or(|r| {
            r.as_ref()
                .is_ok_and(|r| r.as_ref().is_ok_and(|b| b.len() <= 32768))
        });
        if success && status.is_none() {
            status = tokio::select! {biased;_=closed.changed()=>None,_=disconnected.changed()=>None,_=workflow_revision.changed(),if workflow.is_some()=>None,_=selected.changed(),if selection.is_some()=>None,_=tokio::time::sleep_until(deadline)=>None,s=child.wait()=>Some(s)};
        }
        success &= status
            .as_ref()
            .is_some_and(|s| s.as_ref().is_ok_and(|s| s.success()))
            && !*closed.borrow()
            && !*disconnected.borrow()
            && selection.is_none_or(|r| r == *selected.borrow());
        if !success {
            #[cfg(feature = "fixture")]
            host.hooks.wait_async("platform:drain").await;
            pipe.cancel_pending();
            let _ = child.start_kill();
        }
        if status.as_ref().is_none_or(|s| s.is_err()) {
            loop {
                match child.wait().await {
                    Ok(exit) => {
                        status = Some(Ok(exit));
                        break;
                    }
                    Err(_) => {
                        let _ = child.start_kill();
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
        pipe.cancel_pending();
        let written = match writer {
            Ok(w) => w.await.is_ok_and(|r| r.is_ok()),
            Err(_) => false,
        };
        let bytes = match output {
            Some(r) => r,
            None => reader.await,
        };
        self.pids.lock().unwrap().retain(|p| *p != pid);
        self.active.fetch_sub(1, Ordering::SeqCst);
        drop(trusted);
        let unknown = || {
            Error::new(
                503,
                "Browser dispatch may have occurred; completion is not confirmed. No retry was attempted.",
            )
        };
        let read_error = || {
            if browser && was_submitted {
                unknown()
            } else {
                failed()
            }
        };
        let bytes = bytes.map_err(|_| read_error())?.map_err(|_| read_error())?;
        if browser {
            let response: Value = serde_json::from_slice(&bytes).map_err(|_| read_error())?;
            if written
                && bytes.len() <= 32768
                && status
                    .as_ref()
                    .is_some_and(|s| s.as_ref().is_ok_and(|s| s.success()))
                && response["dispatched"] == true
            {
                return Ok(if script == BROWSER {
                    json!({"dispatched":true})
                } else {
                    json!({"dispatched":true,"captured":true})
                });
            }
            return Err(read_error());
        }
        if !success || !written || bytes.len() > 32768 {
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::new(408, "Platform operation expired."));
            }
            return Err(failed());
        }
        serde_json::from_slice(&bytes).map_err(|_| failed())
    }
    pub async fn pick(
        self: &Arc<Self>,
        host: &Arc<Host>,
        mut disconnected: watch::Receiver<bool>,
    ) -> Result<Reply> {
        let (epoch, initial_revision) = {
            let s = host.lock_state();
            if value::boolean(&s.config, value::prop(&s.config, "paused")) == Some(true) {
                return Err(Error::new(409, "本机访问已暂停，请恢复访问后再添加目录。"));
            }
            (s.epoch, self.state.lock().unwrap().revision)
        };
        #[cfg(feature = "fixture")]
        host.hooks.wait_async("platform:register").await;
        let (revision, mode, owner) = {
            // Pause installation takes these locks in the same order and notifies
            // again, including pickers admitted after its earlier invalidation.
            let state = host.lock_state();
            let mut s = self.state.lock().unwrap();
            if value::boolean(&state.config, value::prop(&state.config, "paused")) == Some(true)
                || s.revision != initial_revision
                || host.faulted()
                || host.closing.load(Ordering::SeqCst)
                || s.closed
                || *disconnected.borrow()
            {
                return Ok(Reply::json(json!({"path":null})));
            }
            if s.picker {
                return Err(Error::new(
                    409,
                    "已有文件夹选择窗口打开。请完成或取消该窗口。",
                ));
            }
            s.picker = true;
            (s.revision, s.picker_mode.clone(), self.own())
        };
        let service = self.clone();
        let h = host.clone();
        let signal = disconnected.clone();
        let (send, receive) = oneshot::channel();
        let mut cancelled = self.selection.subscribe();
        let mut closed = self.cancel.subscribe();
        tokio::spawn(async move {
            let _owner = owner;
            let script = script(&mode, PICKER);
            let input = json!({"mode":mode.mode,"path":mode.path,"delayMs":mode.delay_ms});
            let result = service
                .helper(
                    &h,
                    Invocation {
                        workflow: None,
                        epoch,
                        selection: Some(revision),
                        disconnected: signal,
                        script,
                        input,
                        duration: Duration::from_millis(mode.timeout_ms.unwrap_or(120000)),
                        sta: true,
                        browser: false,
                    },
                )
                .await;
            let reply = match result {
                Ok(v) => {
                    let path = v.get("path").filter(|p| {
                        p.is_null() || p.as_str().is_some_and(|s| s.encode_utf16().count() <= 2048)
                    });
                    match path {
                        Some(p) if service.gate(&h, epoch, Some(revision), || Ok(())).is_ok() => {
                            Ok(Reply::json(json!({"path":p})))
                        }
                        Some(_) => Ok(Reply::json(json!({"path":null}))),
                        None => Err(failed()),
                    }
                }
                Err(e) if e.status == 408 || e.status == 409 => {
                    Ok(Reply::json(json!({"path":null})))
                }
                Err(e) => Err(e),
            };
            service.state.lock().unwrap().picker = false;
            let _ = send.send(reply);
        });
        if *disconnected.borrow() || *cancelled.borrow() != revision || *closed.borrow() {
            return Ok(Reply::json(json!({"path":null})));
        }
        tokio::select! {biased;_=disconnected.changed()=>Ok(Reply::json(json!({"path":null}))),_=cancelled.changed()=>Ok(Reply::json(json!({"path":null}))),_=closed.changed()=>Ok(Reply::json(json!({"path":null}))),r=receive=>r.map_err(|_|failed())?}
    }
    pub async fn browse(self: &Arc<Self>, host: &Arc<Host>, input: &Document) -> Result<Reply> {
        value::fields(input, &["path"])?;
        let path = match value::prop(input, "path") {
            None => None,
            Some(id) => Some(
                value::string(input, Some(id))
                    .ok_or_else(|| Error::new(400, "目录路径必须是文字。"))?,
            ),
        };
        let slot = self
            .browse
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::new(429, "目录浏览正忙，请稍后重试。"))?;
        let owner = self.own();
        let host = host.clone();
        let service = self.clone();
        tokio::task::spawn_blocking(move||{let _slot=slot;let _owner=owner;let browse=os::FolderBrowse::open(path.as_deref().filter(|s|!s.is_empty()),host.store.directory()).map_err(|e|Error::new(400,e.message))?;
            #[cfg(feature="fixture")]host.hooks.wait("platform:browse");
            let (entries,truncated)=browse.entries().map_err(|e|Error::new(400,e.message))?;let selectable=browse.selectable();
            let (config,epoch)={let state=host.lock_state();(state.config.try_clone()?,state.epoch)};
            let existing=if selectable{value::array(&config,value::prop(&config,"roots")).unwrap_or_default().into_iter().find(|r|value::string(&config,value::get(&config,*r,"path")).is_some_and(|p|browse.directory.same(std::path::Path::new(&p))))}else{None};
            let mut locations=vec![json!({"label":"用户文件夹","path":browse.home})];for p in [browse.home.ancestors().last(),std::env::current_dir().ok().as_deref().and_then(|p|p.ancestors().last())].into_iter().flatten(){if !locations.iter().any(|v|v["path"]==p.to_string_lossy().as_ref()){locations.push(json!({"label":p,"path":p}));}}
            let mut out=value::parse(json!({"path":browse.directory.path,"parent":browse.directory.path.parent(),"locations":locations,"entries":[],"truncated":truncated,"selectable":selectable,"existingRoot":null,"note":if selectable{"这里只浏览文件夹名称，点击“使用这个文件夹”后才会授予只读权限。"}else{"不能授权整块磁盘、整个用户目录或包含凭据的父目录；请进入一个具体项目文件夹。"}}).to_string().as_bytes())?;
            let mut items=Vec::new();for e in entries{let mut d=value::parse(b"{}")?;value::put(&mut d,"name",J::String(e.name))?;value::put(&mut d,"path",J::String(e.path))?;items.push(out.import(d,usize::MAX)?);}value::put(&mut out,"entries",J::Array(items))?;
            if let Some(r)=existing{let mut d=value::parse(b"{}")?;for key in ["id","label"]{if let Some(id)=value::get(&config,r,key){let id=d.import(value::parse(value::subtree(&config,id)?.as_bytes())?,usize::MAX)?;d.set_property(d.root(),key.encode_utf16().collect(),id)?;}}value::put(&mut d,"writeMode",value::text(&crate::root_mode(&config,r)?))?;let id=out.import(d,usize::MAX)?;out.set_property(out.root(),"existingRoot".encode_utf16().collect(),id)?;}
            let reply=Reply{content_type:"application/json; charset=utf-8",status:200,body:value::serialized(&out)?,cookie:None};service.gate(&host,epoch,None,||Ok(reply))
        }).await.map_err(|_|failed())?
    }
    pub async fn startup(self: &Arc<Self>, host: &Arc<Host>, input: &Document) -> Result<Reply> {
        value::fields(input, &["enabled"])?;
        let enabled = value::boolean(input, value::prop(input, "enabled"))
            .ok_or_else(|| Error::new(400, "An explicit boolean is required."))?;
        #[cfg(not(feature = "fixture"))]
        let directory: Option<PathBuf> =
            if crate::native::startup_eligible(host.store.directory(), &host.origin) {
                Some(os::shell_folder(7).map_err(|_| failed())?)
            } else {
                None
            };
        #[cfg(feature = "fixture")]
        let directory = self.startup.as_ref().map(|s| s.directory.clone());
        let directory=directory.ok_or_else(||Error::new(400,"Login startup is unavailable for a custom development state directory or unsupported system."))?;
        let _owner = self.own();
        let epoch = host.lock_state().epoch;
        let held = os::ShellDirectory::open(&directory).map_err(|_| failed())?;
        let legacy = held.path.join("Chat2Local.lnk");
        let check_legacy = || -> Result<()> {
            if os::ShellFile::open(&legacy)
                .map_err(|_| failed())?
                .is_some()
            {
                return Err(Error::new(
                    409,
                    "Existing Chat2Local startup entry must be managed by its original launcher. Both startup entries were left unchanged.",
                ));
            }
            Ok(())
        };
        check_legacy()?;
        let path = held.path.join(if cfg!(feature = "fixture") {
            "Chat2Local Native Fixture.lnk"
        } else {
            "Chat2Local Native.lnk"
        });
        let old = os::ShellFile::open(&path).map_err(|_| failed())?;
        let temporary = held
            .path
            .join(format!(".chat2local-{}.lnk", crate::random(16)?));
        let target = std::env::current_exe()?;
        let manifest: Value = serde_json::from_slice(&std::fs::read(
            target.parent().ok_or_else(failed)?.join("manifest.json"),
        )?)
        .map_err(|_| failed())?;
        if manifest["fixtureOnly"] != cfg!(feature = "fixture")
            || manifest["fullAgent"] != false
            || manifest["executable"].as_str() != target.file_name().and_then(|s| s.to_str())
        {
            return Err(failed());
        }
        let target_hash = manifest["sha256"].as_str().ok_or_else(failed)?;
        let _target = os::TrustedExecutable::open(&target, target_hash).map_err(|_| failed())?;
        let previous = held
            .path
            .join(format!(".chat2local-previous-{}.lnk", crate::random(16)?));
        let snapshot = if let Some(old) = &old {
            let bytes = old.snapshot().map_err(|_| failed())?;
            Some(self.gate(host, epoch, None, || {
                use std::io::{Read, Write};
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&previous)?;
                file.write_all(&bytes)?;
                let identity = os::shell_file_identity(&file).map_err(|_| failed())?;
                drop(file);
                let mut held = os::hold_shell_read(&previous).map_err(|_| failed())?;
                let mut copy = Vec::new();
                (&mut held).take(1024 * 1024 + 1).read_to_end(&mut copy)?;
                if os::shell_file_identity(&held).map_err(|_| failed())? != identity
                    || copy != bytes
                {
                    return Err(Error::new(
                        503,
                        "Startup inspection copy changed; original preserved.",
                    ));
                }
                Ok(held)
            })?)
        } else {
            None
        };
        let input = json!({"enabled":enabled,"previous":if snapshot.is_some(){Some(&previous)}else{None},"temporary":temporary,"target":target,"working":target.parent(),"arguments":if cfg!(feature="fixture"){"--fixture-startup-unavailable"}else{"--background"}});
        let (_signal, rx) = watch::channel(false);
        let prepared = self
            .helper(
                host,
                Invocation {
                    workflow: None,
                    epoch,
                    selection: None,
                    disconnected: rx,
                    script: STARTUP,
                    input,
                    duration: Duration::from_secs(30),
                    sta: false,
                    browser: false,
                },
            )
            .await;
        let mut produced = None;
        let mut attempted = false;
        let mut old = old;
        let result=async {
            let receipt=prepared?;
            if receipt["prepared"]!=true{return Err(failed());}
            if enabled {
                let file=os::ShellFile::open(&temporary).map_err(|_|failed())?.ok_or_else(failed)?;
                let bytes=file.snapshot().map_err(|_|failed())?;
                if receipt["sha256"].as_str()!=Some(hex::encode(openssl::sha::sha256(&bytes)).as_str()) {return Err(Error::new(503,"Prepared startup file changed; prior shortcut and replacement were preserved."));}
                produced=Some(file);
            }
            #[cfg(feature="fixture")]host.hooks.wait_async("platform:commit").await;
            self.gate(host,epoch,None,|| {
                check_legacy()?;
                if let Some(previous)=old.take(){previous.delete().map_err(|_|failed())?;}
                if let Some(new)=&produced {attempted=true;new.publish(&path).map_err(|_|Error::new(503,"Startup publication failed after the checked prior link was removed or while the target changed; OS outcome is partial and no rollback was attempted."))?;}
                Ok(())
            })?;
            let (receive,next_epoch,previous)={let mut s=host.lock_state();if host.faulted()||host.closing.load(Ordering::SeqCst)||s.epoch!=epoch{return Err(Error::new(503,"Startup OS action applied, but config save was not admitted."));}let previous=s.config.try_clone()?;let mut next=s.config.try_clone()?;value::put(&mut next,"startup",J::Bool(enabled))?;let receive=host.persistence.config(next.try_clone()?).map_err(|_|Error::new(503,"Startup OS action applied, but config save was not admitted."))?;s.config=next;s.epoch+=1;(receive,s.epoch,previous)};
            if crate::persistence::confirmed(receive,false).await.is_err(){let mut s=host.lock_state();if s.epoch==next_epoch&&!host.faulted()&&!host.closing.load(Ordering::SeqCst){s.config=previous;s.epoch+=1;}return Err(Error::new(503,"Startup OS action applied, but config persistence failed; no rollback was attempted."));}
            Ok(Reply::json(json!({"enabled":enabled})))
        }.await;
        let snapshot_id = snapshot
            .as_ref()
            .and_then(|f| os::shell_file_identity(f).ok());
        drop(snapshot);
        if host.store.check_owner().is_ok() {
            if let (Some(expected), Ok(Some(copy))) = (snapshot_id, os::ShellFile::open(&previous))
                && copy.identity().ok() == Some(expected)
            {
                let _ = copy.delete();
            }
            if !attempted && let Some(file) = produced.take() {
                let _ = file.delete();
            }
        }
        result
    }
    #[cfg_attr(
        not(feature = "fixture"),
        expect(
            dead_code,
            reason = "Reserved internal browser adapter; this partial host has no launcher browser flow."
        )
    )]
    pub async fn browser(self: &Arc<Self>, host: &Arc<Host>, target: &Value) -> Result<Value> {
        self.browser_inner(host, target, None).await
    }
    pub async fn browser_workflow(
        self: &Arc<Self>,
        host: &Arc<Host>,
        target: &Value,
        guard: crate::workflow::Guard,
    ) -> Result<Value> {
        self.browser_inner(host, target, Some(guard)).await
    }
    async fn browser_inner(
        self: &Arc<Self>,
        host: &Arc<Host>,
        target: &Value,
        workflow: Option<crate::workflow::Guard>,
    ) -> Result<Value> {
        let slot = self
            .browser_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::new(429, "Browser dispatch capacity reached."))?;
        let url = target["url"]
            .as_str()
            .filter(|s| s.len() <= 4096)
            .ok_or_else(|| Error::new(400, "Invalid internal browser target."))?;
        let parsed = url::Url::parse(url).map_err(|_| stale())?;
        let epoch = {
            let s = host.lock_state();
            let valid = match target["kind"].as_str() {
                Some("local-panel") => url == format!("{}/folders#{}", host.origin, host.token),
                Some("relay-handoff") => crate::tools::identity(&s.secrets).is_ok_and(|i| {
                    parsed.origin().ascii_serialization() == i.origin
                        && parsed.path() == "/link"
                        && parsed.fragment().is_some_and(|f| {
                            f.strip_prefix(&(i.device + ".")).is_some_and(|p| {
                                p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                        })
                }),
                _ => false,
            };
            if !valid
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || !["http", "https"].contains(&parsed.scheme())
            {
                return Err(Error::new(400, "Invalid internal browser target."));
            }
            s.epoch
        };
        let owner = self.own();
        let host = host.clone();
        let service = self.clone();
        let mode = self.state.lock().unwrap().browser_mode.clone();
        let url = url.to_owned();
        let (send, receive) = oneshot::channel();
        tokio::spawn(async move {
            let _owner = owner;
            let _slot = slot;
            let script = script(&mode, BROWSER);
            #[cfg(feature = "fixture")]
            host.hooks.wait_async("platform:commit").await;
            let (_signal, rx) = watch::channel(false);
            let r = service
                .helper(
                    &host,
                    Invocation {
                        disconnected: workflow
                            .as_ref()
                            .map(|g| g.disconnected.clone())
                            .unwrap_or(rx),
                        workflow,
                        epoch,
                        selection: None,
                        script,
                        input: json!({"url":url,"mode":mode.mode,"delayMs":mode.delay_ms}),
                        duration: Duration::from_millis(mode.timeout_ms.unwrap_or(30000)),
                        sta: false,
                        browser: true,
                    },
                )
                .await;
            let _ = send.send(r);
        });
        receive.await.map_err(|_| failed())?
    }
}
