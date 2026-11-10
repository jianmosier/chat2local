//! Nonfixture entry and read-only launcher. A ready receipt never contains a capability.
use crate::{Error, Options, Result, value};
use chat2local_agent_platform::{self as os, ProcessOwner, TrustedExecutable};
use chat2local_native_store::Store;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

fn refuse() -> Error {
    Error::new(
        503,
        "Existing controller or native package cannot be verified. Use normal Quit in its original panel, then rerun the installer. No replacement, retry or termination was attempted.",
    )
}
pub fn default_directory() -> Result<PathBuf> {
    let env = std::env::vars().collect::<BTreeMap<_, _>>();
    let home = os::shell_folder(0x28).map_err(|_| refuse())?;
    Ok(PathBuf::from(
        chat2local_native_store::location::state_directory(
            &chat2local_native_store::location::Location {
                env: &env,
                platform: "win32",
                home: home.to_str().ok_or_else(refuse)?,
            },
        ),
    ))
}
pub(crate) fn is_default_directory(directory: &Path) -> bool {
    // An explicit state override is development mode even if it happens to spell the default.
    if std::env::var_os("CHAT2LOCAL_STATE_DIR").is_some() {
        return false;
    }
    default_directory().is_ok_and(|path| path == directory)
}
pub(crate) fn startup_eligible(directory: &Path, origin: &str) -> bool {
    !cfg!(feature = "fixture")
        && origin == "http://127.0.0.1:47631"
        && is_default_directory(directory)
}
fn clear_standard_inheritance() -> Result<()> {
    unsafe extern "system" {
        fn GetStdHandle(which: u32) -> *mut std::ffi::c_void;
        fn SetHandleInformation(handle: *mut std::ffi::c_void, mask: u32, flags: u32) -> i32;
    }
    // Rust Command duplicates its selected stdio, but Windows also inherits other
    // inheritable handles. Do not leak our caller's capture pipes into a detached
    // host or propagate the one-shot ready pipe into later helpers.
    for which in [-10i32, -11, -12] {
        let handle = unsafe { GetStdHandle(which as u32) };
        if !handle.is_null()
            && handle as isize != -1
            && unsafe { SetHandleInformation(handle, 1, 0) } == 0
        {
            return Err(refuse());
        }
    }
    Ok(())
}
struct Package {
    executable: PathBuf,
    _image: TrustedExecutable,
    _runner: TrustedExecutable,
    _runtime: Vec<TrustedExecutable>,
}
fn package() -> Result<Package> {
    let executable = std::env::current_exe()?;
    let parent = executable.parent().ok_or_else(refuse)?;
    let bytes = std::fs::read(parent.join("manifest.json"))?;
    if bytes.len() > 1024 * 1024 {
        return Err(refuse());
    }
    let manifest: Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    if manifest["v"] != 1
        || manifest["fixtureOnly"] != false
        || manifest["fullAgent"] != false
        || manifest["upgradeReady"] != false
        || manifest["executable"].as_str() != executable.file_name().and_then(|s| s.to_str())
        || manifest["terminalRunner"]["fixtureOnly"] != false
        || manifest["terminalRunner"]["executable"] != "chat2local-terminal-runner.exe"
        || manifest["capabilities"] != crate::version()
        || manifest["features"] != json!([])
        || manifest["platform"] != "win32"
        || manifest["architecture"] != "x64"
    {
        return Err(refuse());
    }
    let image =
        TrustedExecutable::open(&executable, manifest["sha256"].as_str().ok_or_else(refuse)?)
            .map_err(|_| refuse())?;
    let runner = TrustedExecutable::open(
        &parent.join("chat2local-terminal-runner.exe"),
        manifest["terminalRunner"]["sha256"]
            .as_str()
            .ok_or_else(refuse)?,
    )
    .map_err(|_| refuse())?;
    let mut runtime = Vec::new();
    if let Some(dependencies) = manifest.get("runtimeDependencies") {
        for (name, digest) in dependencies.as_object().ok_or_else(refuse)? {
            if name != "vcruntime140.dll" {
                return Err(refuse());
            }
            runtime.push(
                TrustedExecutable::open(&parent.join(name), digest.as_str().ok_or_else(refuse)?)
                    .map_err(|_| refuse())?,
            );
        }
    }
    Ok(Package {
        executable,
        _image: image,
        _runner: runner,
        _runtime: runtime,
    })
}
struct Session {
    process: ProcessOwner,
    bytes: Vec<u8>,
    directory: PathBuf,
    origin: String,
    token: String,
    instance: String,
    pid: u32,
}
impl Session {
    fn current(&self) -> Result<()> {
        if self.process.exited().map_err(|_| refuse())?
            || std::fs::read(self.directory.join("session.json"))? != self.bytes
        {
            return Err(refuse());
        }
        Ok(())
    }
    fn public(&self, reused: bool) -> Value {
        json!({"name":crate::NAME,"fixtureOnly":false,"fullAgent":false,"upgradeReady":false,"origin":self.origin,"instanceId":self.instance,"pid":self.pid,"reused":reused})
    }
}
struct Inspection {
    session: Option<Session>,
    _dead: Option<ProcessOwner>,
}
fn inspect(directory: &Path, port: u16, executable: &Path) -> Result<Inspection> {
    let bytes = match std::fs::read(directory.join("session.json")) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Inspection {
                session: None,
                _dead: None,
            });
        }
        Err(_) => return Err(refuse()),
    };
    let saved = Store::new(directory).read_session().map_err(|_| refuse())?;
    let pid = value::number(&saved, value::prop(&saved, "pid"))
        .filter(|p| *p > 0.0 && *p <= u32::MAX as f64 && p.fract() == 0.0)
        .ok_or_else(refuse)? as u32;
    let metadata = crate::owner::metadata(&saved).map_err(|_| refuse())?;
    if std::fs::read(directory.join("session.json"))? != bytes {
        return Err(refuse());
    }
    let process = ProcessOwner::open(pid).map_err(|_| refuse())?;
    if std::fs::read(directory.join("session.json"))? != bytes {
        return Err(refuse());
    }
    let Some(process) = process else {
        return Ok(Inspection {
            session: None,
            _dead: None,
        });
    };
    let observed = process.probe().map_err(|_| refuse())?;
    let dead = crate::owner::dead(&metadata, &observed).map_err(|_| refuse())?;
    if std::fs::read(directory.join("session.json"))? != bytes {
        return Err(refuse());
    }
    if dead {
        return Ok(Inspection {
            session: None,
            _dead: Some(process),
        });
    }
    let image = observed.image.map_err(|_| refuse())?;
    let origin = format!("http://127.0.0.1:{port}");
    let token = value::string(&saved, value::prop(&saved, "token"))
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(refuse)?;
    let instance =
        crate::consent::identifier(value::string(&saved, value::prop(&saved, "instanceId")))
            .map_err(|_| refuse())?;
    if value::string(&saved, value::prop(&saved, "profile")).as_deref() != Some(crate::NAME)
        || value::boolean(&saved, value::prop(&saved, "fixtureOnly")) != Some(false)
        || value::boolean(&saved, value::prop(&saved, "fullAgent")) != Some(false)
        || value::string(&saved, value::prop(&saved, "origin")).as_deref() != Some(&origin)
        || Path::new(&image) != executable
    {
        return Err(refuse());
    }
    let session = Session {
        process,
        bytes,
        directory: directory.to_owned(),
        origin,
        token,
        instance,
        pid,
    };
    session.current()?;
    let mut socket = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    )
    .map_err(|_| refuse())?;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    socket.write_all(format!("GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Chat2Local-Token: {}\r\nConnection: close\r\n\r\n",session.token).as_bytes())?;
    let response = bounded_response(&mut socket, deadline)?;
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(refuse)?;
    if response.len() > 1024 * 1024 || !response.starts_with(b"HTTP/1.1 200 ") {
        return Err(refuse());
    }
    let status = value::parse(&response[split + 4..]).map_err(|_| refuse())?;
    if !runtime_matches(&status)
        || value::string(&status, value::prop(&status, "instanceId")).as_deref()
            != Some(&session.instance)
    {
        return Err(refuse());
    }
    session.current()?;
    Ok(Inspection {
        session: Some(session),
        _dead: None,
    })
}
fn runtime_matches(status: &chat2local_js_value_compat::Document) -> bool {
    // Status also carries legacy roots, including unknown UTF-16 values. Parse
    // those losslessly and project only the strict public runtime contract.
    crate::version()
        .as_object()
        .unwrap()
        .iter()
        .all(|(key, expected)| {
            key == "terminalAvailable"
                || value::prop(status, key)
                    .and_then(|id| value::subtree(status, id).ok())
                    .and_then(|json| serde_json::from_str::<Value>(&json).ok())
                    .as_ref()
                    == Some(expected)
        })
}
fn bounded_response(
    socket: &mut std::net::TcpStream,
    deadline: std::time::Instant,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or_else(refuse)?;
        socket.set_read_timeout(Some(remaining))?;
        let n = socket.read(&mut buffer).map_err(|_| refuse())?;
        if n == 0 {
            return Ok(bytes);
        }
        if bytes.len() + n > 1024 * 1024 {
            return Err(refuse());
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
}
fn vacant(port: u16) -> Result<()> {
    use std::os::windows::io::AsRawSocket;
    let socket = tokio::net::TcpSocket::new_v4()?;
    os::exclusive_socket(socket.as_raw_socket())?;
    socket.bind(std::net::SocketAddr::from(([127, 0, 0, 1], port)))?;
    Ok(())
}
fn shutdown(session: Session, port: u16) -> Result<()> {
    session.current()?;
    let mut socket = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    )
    .map_err(|_| refuse())?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    session.current()?;
    // Submit once. A lost response must never cause another shutdown request.
    socket.write_all(format!("POST /api/shutdown HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {}\r\nX-Chat2Local-Token: {}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}",session.origin,session.token).as_bytes())?;
    let _response = bounded_response(
        &mut socket,
        std::time::Instant::now() + Duration::from_secs(3),
    );
    drop(socket);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if std::fs::read(session.directory.join("session.json"))? != session.bytes {
            return Err(refuse());
        }
        if session.process.exited().map_err(|_| refuse())? {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::new(
                503,
                "Normal shutdown was submitted once, but process exit is not confirmed. No force termination or retry was attempted.",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    vacant(port).map_err(|_| Error::new(503, "Owned process exited, but the local port is occupied. No replacement or termination was attempted."))?;
    println!(
        "{}",
        json!({"name":crate::NAME,"fixtureOnly":false,"fullAgent":false,"upgradeReady":false,"stopped":true,"pid":session.pid})
    );
    Ok(())
}
fn management_content(executable: &Path, directory: &Path, port: u16) -> Result<String> {
    let package = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(refuse)?;
    let release = package
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(refuse)?;
    if executable.file_name().and_then(|v| v.to_str()) != Some("chat2local-native-agent.exe")
        || executable
            .parent()
            .and_then(Path::file_name)
            .and_then(|v| v.to_str())
            != Some("native")
        || package.parent() != Some(directory.join("apps").as_path())
        || release.is_empty()
        || release.len() > 160
        || !release
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || release == "."
        || release == ".."
        || port == 0
    {
        return Err(Error::new(
            409,
            "Management entry requires a verified package in its apps directory with an ASCII release name.",
        ));
    }
    Ok(format!(
        "@echo off\r\nrem chat2local-managed-entry-v1\r\nsetlocal DisableDelayedExpansion\r\n\"%~dp0apps\\{release}\\native\\chat2local-native-agent.exe\" --launch --state-dir \"%~dp0.\" --port {port}\r\nif errorlevel 1 pause\r\n"
    ))
}
fn activate_entry(session: Session, executable: &Path, directory: &Path, port: u16) -> Result<()> {
    let held = os::ShellDirectory::open(directory).map_err(|_| refuse())?;
    if !held.same(&session.directory) {
        return Err(Error::new(
            409,
            "Management entry must belong to the original state directory; no entry was changed.",
        ));
    }
    let target = held.path.join("Chat2Local.cmd");
    let old = os::ShellFile::open(&target).map_err(|_| refuse())?;
    let prior = old
        .as_ref()
        .map(|f| f.snapshot().map_err(|_| refuse()))
        .transpose()?;
    let content = management_content(executable, &held.path, port)?;
    if let Some(bytes) = &prior {
        if !bytes.starts_with(b"@echo off\r\nrem chat2local-managed-entry-v1\r\n")
            || bytes.len() > 16384
        {
            return Err(Error::new(409, "Unrelated management entry was retained."));
        }
        if bytes == content.as_bytes() {
            session.current()?;
            println!(
                "{}",
                json!({"name":crate::NAME,"fixtureOnly":false,"fullAgent":false,"upgradeReady":false,"entryActivated":true,"updated":false,"managementEntry":target})
            );
            return Ok(());
        }
    }
    let temporary = held
        .path
        .join(format!(".chat2local-entry-{}.tmp", crate::random(16)?));
    let backup = held
        .path
        .join(format!("Chat2Local.cmd.previous-{}", crate::random(16)?));
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        let prepared = os::ShellFile::open(&temporary)
            .map_err(|_| refuse())?
            .ok_or_else(refuse)?;
        if prepared.snapshot().map_err(|_| refuse())? != content.as_bytes() {
            return Err(refuse());
        }
        // The exact new process object and session generation remain held across
        // the final check and atomic publication. Launch failure never gets here.
        session.current()?;
        if old.is_none() {
            prepared.publish(&target).map_err(|_| refuse())?;
        } else {
            // Retain verified old bytes before the atomic handle publication.
            // ReplaceFileW previously failed here with Windows error 1175.
            let mut copy = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&backup)?;
            copy.write_all(prior.as_ref().ok_or_else(refuse)?)?;
            copy.sync_all()?;
            drop(copy);
            let saved = os::ShellFile::open(&backup)
                .map_err(|_| refuse())?
                .ok_or_else(refuse)?;
            if saved.snapshot().map_err(|_| refuse())? != *prior.as_ref().ok_or_else(refuse)? {
                return Err(refuse());
            }
            session.current()?;
            prepared.replace_checked(&target, old.ok_or_else(refuse)?).map_err(|_| Error::new(503, "Management entry replacement was not confirmed. The verified previous bytes were retained; no rollback or restart was attempted."))?;
        }
        session.current()?;
        println!(
            "{}",
            json!({"name":crate::NAME,"fixtureOnly":false,"fullAgent":false,"upgradeReady":false,"entryActivated":true,"updated":true,"managementEntry":target})
        );
        Ok(())
    })();
    let _ = std::fs::remove_file(&temporary);
    result
}
fn ready_stdout(value: &Value) -> Result<()> {
    // Transfer the inherited ready pipe once. Closing it does not terminate the background host.
    use std::os::windows::io::FromRawHandle;
    unsafe extern "system" {
        fn GetStdHandle(which: u32) -> *mut std::ffi::c_void;
        fn SetStdHandle(which: u32, handle: *mut std::ffi::c_void) -> i32;
    }
    let handle = unsafe { GetStdHandle((-11i32) as u32) };
    if handle.is_null() || handle as isize == -1 {
        return Err(refuse());
    }
    unsafe {
        SetStdHandle((-11i32) as u32, std::ptr::null_mut());
    }
    let mut output = unsafe { std::fs::File::from_raw_handle(handle) };
    writeln!(output, "{value}")?;
    output.flush()?;
    Ok(())
}
async fn panel(session: &Session) -> Result<()> {
    session.current()?;
    let trusted = os::system_powershell().map_err(|_| refuse())?;
    let (pipe, input) = os::ControlPipe::pair(&crate::random(32)?).map_err(|_| refuse())?;
    let script = "$ErrorActionPreference='Stop';[Console]::InputEncoding=New-Object Text.UTF8Encoding($false);[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false);$c=([Console]::In.ReadLine()|ConvertFrom-Json);Start-Process -FilePath $c.url;@{dispatched=$true}|ConvertTo-Json -Compress";
    let mut command = tokio::process::Command::new(&trusted.path);
    let windows = trusted.path.ancestors().nth(4).ok_or_else(refuse)?;
    command
        .env_clear()
        .env("SystemRoot", windows)
        .env(
            "SystemDrive",
            windows.components().next().ok_or_else(refuse)?.as_os_str(),
        )
        .current_dir(&session.directory)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .creation_flags(0x08000000);
    session.current()?;
    let mut child = command.spawn()?;
    drop(command);
    let stdout = child.stdout.take().ok_or_else(refuse)?;
    let reader = tokio::spawn(async move {
        let mut b = Vec::new();
        stdout.take(32769).read_to_end(&mut b).await.map(|_| b)
    });
    let write = session.current().and_then(|()| {
        pipe.submit(
            format!(
                "{}\n",
                json!({"url":format!("{}/folders#{}",session.origin,session.token)})
            )
            .into_bytes(),
        )
        .map_err(|_| refuse())
    });
    let submitted = write.is_ok();
    let writer = write.map(|s| tokio::task::spawn_blocking(move || s.complete()));
    let status = if submitted {
        tokio::time::timeout(Duration::from_secs(30), child.wait())
            .await
            .ok()
            .and_then(std::result::Result::ok)
    } else {
        None
    };
    if status.is_none() {
        pipe.cancel_pending();
        let _ = child.start_kill();
        loop {
            if child.wait().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    pipe.cancel_pending();
    let written = match writer {
        Ok(w) => w.await.is_ok_and(|r| r.is_ok()),
        Err(_) => false,
    };
    let output = reader.await.ok().and_then(std::result::Result::ok);
    if written
        && status.is_some_and(|s| s.success())
        && output.is_some_and(|b| {
            b.len() <= 32768
                && serde_json::from_slice::<Value>(&b).is_ok_and(|v| v["dispatched"] == true)
        })
    {
        return Ok(());
    }
    Err(Error::new(
        503,
        if submitted {
            "Browser dispatch may have occurred; completion is not confirmed. No retry was attempted."
        } else {
            "Browser command was not submitted."
        },
    ))
}
pub async fn entry(args: Vec<String>) -> Result<()> {
    if cfg!(feature = "fixture") {
        return Err(Error::new(
            503,
            "Formal executable refuses fixture-enabled linkage.",
        ));
    }
    if args == ["--version"] {
        println!("{}", crate::version());
        return Ok(());
    }
    clear_standard_inheritance()?;
    let mut background = false;
    let mut selected = false;
    let mut ready = false;
    let mut no_browser = false;
    let mut preflight = false;
    let mut stopping = false;
    let mut activation = None;
    let mut directory = None;
    let mut port = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--activate-entry" if !selected && i + 1 < args.len() => {
                selected = true;
                activation = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--launch" | "--background" | "--preflight" | "--shutdown" if !selected => {
                selected = true;
                background = args[i] == "--background";
                preflight = args[i] == "--preflight";
                stopping = args[i] == "--shutdown";
                i += 1;
            }
            "--ready-stdout" if !ready => {
                ready = true;
                i += 1;
            }
            "--no-browser" if !no_browser => {
                no_browser = true;
                i += 1;
            }
            "--state-dir" if directory.is_none() && i + 1 < args.len() => {
                directory = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--port" if port.is_none() && i + 1 < args.len() => {
                port = Some(
                    args[i + 1]
                        .parse::<u16>()
                        .map_err(|_| Error::new(400, "Invalid local port."))?,
                );
                i += 2;
            }
            _ => return Err(Error::new(400, "Unsupported native argument.")),
        }
    }
    if (ready && !background) || ((preflight || stopping || activation.is_some()) && no_browser) {
        return Err(Error::new(400, "Ready output belongs to background mode."));
    }
    let directory = directory.map(Ok).unwrap_or_else(default_directory)?;
    let port = port.unwrap_or(47631);
    if !directory.is_absolute() || port == 0 {
        return Err(Error::new(
            400,
            "Absolute state directory and nonzero port required.",
        ));
    }
    let directory: PathBuf = directory.components().collect();
    let package = package()?;
    if !stopping {
        chat2local_native_store::assert_write_fence_clear(&directory)?;
    }
    if background {
        return crate::run(Options::new(directory,port),move|r|{if ready{let _=ready_stdout(&json!({"name":crate::NAME,"fixtureOnly":false,"fullAgent":false,"upgradeReady":false,"origin":r.origin,"instanceId":r.instance_id,"port":r.port,"pid":std::process::id()}));}}).await;
    }
    let lookup = |directory: PathBuf, executable: PathBuf| {
        tokio::task::spawn_blocking(move || inspect(&directory, port, &executable))
    };
    let prior = lookup(directory.clone(), package.executable.clone())
        .await
        .map_err(|_| refuse())??;
    let _dead = prior._dead;
    if let Some(entry) = activation {
        if !entry.is_absolute() {
            return Err(refuse());
        }
        let session = prior.session.ok_or_else(refuse)?;
        return activate_entry(session, &package.executable, &entry, port);
    }
    if stopping {
        let session = prior.session.ok_or_else(|| Error::new(409, "No running instance of this exact package was verified. No shutdown request was sent."))?;
        return tokio::task::spawn_blocking(move || shutdown(session, port))
            .await
            .map_err(|_| refuse())?;
    }
    if preflight {
        if let Some(session) = prior.session {
            session.current()?;
            let mut receipt = session.public(true);
            receipt["running"] = json!(true);
            receipt["stopped"] = json!(false);
            println!("{receipt}");
        } else {
            vacant(port)?;
            println!(
                "{}",
                json!({"name":crate::NAME,"fixtureOnly":false,"fullAgent":false,"upgradeReady":false,"running":false,"stopped":true})
            );
        }
        return Ok(());
    }
    let (session, reused) = if let Some(session) = prior.session {
        (session, true)
    } else {
        // Read-only port check. The child independently reserves it before touching Store.
        vacant(port)?;
        let mut command = tokio::process::Command::new(&package.executable);
        command
            .args(["--background", "--ready-stdout", "--state-dir"])
            .arg(&directory)
            .args(["--port", &port.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(0x00000008 | 0x00000200);
        let mut child = command.spawn()?;
        drop(command);
        let pid = child.id().ok_or_else(refuse)?;
        let stdout = child.stdout.take().ok_or_else(refuse)?;
        let mut reader = BufReader::new(stdout).take(4097);
        let mut bytes = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(15),
            reader.read_until(b'\n', &mut bytes),
        )
        .await
        .map_err(|_| refuse())??;
        if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
            return Err(refuse());
        }
        let receipt: Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
        let session = lookup(directory, package.executable.clone())
            .await
            .map_err(|_| refuse())??
            .session
            .ok_or_else(refuse)?;
        if receipt["name"] != crate::NAME
            || receipt["fixtureOnly"] != false
            || receipt["fullAgent"] != false
            || receipt["pid"] != pid
            || session.pid != pid
            || receipt["instanceId"] != session.instance
            || receipt["origin"] != session.origin
        {
            return Err(refuse());
        }
        // Dropping Child with kill_on_drop=false intentionally leaves the owned background host alive.
        drop(child);
        (session, false)
    };
    if !no_browser && std::env::var("CHAT2LOCAL_NO_BROWSER").as_deref() != Ok("1") {
        panel(&session).await?;
    }
    println!("{}", session.public(reused));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_profile_requires_exact_version_and_contract() {
        let original = crate::version();
        assert!(runtime_matches(
            &value::parse(original.to_string().as_bytes()).unwrap()
        ));
        for (key, replacement) in [
            ("version", json!("0.1.0-alpha.27")),
            ("routes", json!([])),
            ("fullAgent", json!(true)),
            ("name", json!("chat2local")),
            ("openssl", json!("other")),
        ] {
            let mut changed = original.clone();
            changed[key] = replacement;
            assert!(!runtime_matches(
                &value::parse(changed.to_string().as_bytes()).unwrap()
            ));
        }
    }
    #[test]
    fn runtime_status_keeps_unknown_lone_surrogates_out_of_strict_projection() {
        let mut wire = crate::version().to_string();
        wire.pop();
        wire.push_str(r#", "roots":[{"opaque":{"keep":["中文","\ud800"]}}]}"#);
        assert!(serde_json::from_str::<Value>(&wire).is_err());
        let status = value::parse(wire.as_bytes()).unwrap();
        assert!(runtime_matches(&status));
        assert!(value::serialized(&status).unwrap().contains(r#"\ud800"#));
    }
    #[test]
    fn trickled_response_has_a_whole_operation_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            for _ in 0..100 {
                if socket.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let mut client = std::net::TcpStream::connect(address).unwrap();
        let start = std::time::Instant::now();
        assert!(bounded_response(&mut client, start + Duration::from_millis(120)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(client);
        writer.join().unwrap();
    }
    #[test]
    fn custom_port_never_installs_default_endpoint_startup() {
        let directory = default_directory().unwrap();
        assert!(!startup_eligible(&directory, "http://127.0.0.1:12345"));
    }
    #[test]
    fn native_management_entry_quotes_paths_without_node_fallback() {
        let parent = Path::new(r#"C:\中文 space & path\100%"#);
        let entry = management_content(
            &parent.join(
                r#"apps\0.1.0-alpha.29-win32-x64-0123456789ab\native\chat2local-native-agent.exe"#,
            ),
            parent,
            12345,
        )
        .unwrap();
        assert!(entry.contains(r#""%~dp0apps\0.1.0-alpha.29-win32-x64-0123456789ab\native\chat2local-native-agent.exe" --launch --port 12345"#));
        assert!(entry.is_ascii());
        assert!(!entry.contains("node"));
        assert!(
            management_content(
                &parent.join(r#"apps\非ASCII\native\chat2local-native-agent.exe"#),
                parent,
                12345
            )
            .is_err()
        );
    }
}
