use super::*;
use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::atomic::AtomicUsize;
use std::time::Instant;
use windows_sys::Win32::{
    Foundation::*,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::*,
    System::{JobObjects::*, Pipes::CreatePipe, Threading::*},
};

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn owned(handle: HANDLE) -> Result<OwnedHandle, &'static str> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err("EWIN32")
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}
fn quote(value: &str) -> String {
    let mut result = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        result.push_str(&"\\".repeat(if ch == '"' { slashes * 2 + 1 } else { slashes }));
        slashes = 0;
        result.push(ch);
    }
    result.push_str(&"\\".repeat(slashes * 2));
    result.push('"');
    result
}
struct Attributes {
    _storage: Vec<usize>,
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
}
impl Attributes {
    fn new(handles: &mut [HANDLE; 3], jobs: &mut [HANDLE; 1]) -> Result<Self, &'static str> {
        let mut size = 0;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size);
        }
        if size == 0 || size > 65536 {
            return Err("EATTRIBUTES");
        }
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        let pointer = storage.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(pointer, 2, 0, &mut size) } == 0 {
            return Err("EATTRIBUTES");
        }
        let list = Self {
            _storage: storage,
            pointer,
        };
        if unsafe {
            UpdateProcThreadAttribute(
                pointer,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_mut_ptr().cast(),
                size_of_val(handles),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err("EATTRIBUTES");
        }
        // Attach atomically during creation: even a helper crash before the
        // suspended process is inspected cannot leave an unowned child.
        if unsafe {
            UpdateProcThreadAttribute(
                pointer,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_mut_ptr().cast(),
                size_of_val(jobs),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err("EATTRIBUTES");
        }
        Ok(list)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.pointer);
        }
    }
}
fn pipe() -> Result<(File, OwnedHandle), &'static str> {
    let mut reader = null_mut();
    let mut writer = null_mut();
    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    if unsafe { CreatePipe(&mut reader, &mut writer, &security, 0) } == 0 {
        return Err("EPIPE");
    }
    let reader = owned(reader)?;
    let writer = owned(writer)?;
    if unsafe { SetHandleInformation(reader.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err("EPIPE");
    }
    Ok((File::from(reader), writer))
}
struct Process {
    job: OwnedHandle,
    process: OwnedHandle,
    thread: OwnedHandle,
    stdout: File,
    stderr: File,
    pid: u32,
}
fn create(prepare: &Prepare) -> Result<Process, (&'static str, bool)> {
    create_checked(prepare, belongs_to_job)
}
fn belongs_to_job(job: HANDLE, process: HANDLE) -> bool {
    let mut member = 0;
    unsafe { IsProcessInJob(process, job, &mut member) != 0 && member != 0 }
}
fn create_checked(
    prepare: &Prepare,
    check: impl FnOnce(HANDLE, HANDLE) -> bool,
) -> Result<Process, (&'static str, bool)> {
    let build = || -> Result<_, &'static str> {
        let job = owned(unsafe { CreateJobObjectW(null(), null()) })?;
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err("EJOB");
        }
        let (stdout, out_write) = pipe()?;
        let (stderr, err_write) = pipe()?;
        let security = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let stdin = owned(unsafe {
            CreateFileW(
                wide("NUL").as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &security,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        })?;
        Ok((job, stdout, out_write, stderr, err_write, stdin))
    };
    let (job, stdout, out_write, stderr, err_write, stdin) =
        build().map_err(|code| (code, true))?;
    let mut handles = [
        stdin.as_raw_handle(),
        out_write.as_raw_handle(),
        err_write.as_raw_handle(),
    ];
    let mut jobs = [job.as_raw_handle()];
    let attributes = Attributes::new(&mut handles, &mut jobs).map_err(|code| (code, true))?;
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes.pointer;
    let system = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let file = format!(
        "{}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        system.trim_end_matches('\\')
    );
    let wrapper = format!(
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $global:LASTEXITCODE = 0; & {{ {}\n}}; if (-not $?) {{ exit 1 }}; exit $LASTEXITCODE",
        prepare.command
    );
    let mut command = wide(
        &[
            file.as_str(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &wrapper,
        ]
        .map(quote)
        .join(" "),
    );
    if command.len() > 32767 {
        return Err(("ECOMMAND", true));
    }
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        CreateProcessW(
            wide(&file).as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            null(),
            wide(&prepare.cwd).as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    } == 0
    {
        return Err(("ESPAWN", true));
    }
    let process = owned(info.hProcess).map_err(|code| (code, false))?;
    let thread = owned(info.hThread).map_err(|code| (code, false))?;
    if !check(job.as_raw_handle(), process.as_raw_handle()) {
        unsafe {
            TerminateProcess(process.as_raw_handle(), 1);
        }
        let confirmed =
            unsafe { WaitForSingleObject(process.as_raw_handle(), 3000) } == WAIT_OBJECT_0;
        return Err(("EASSIGN", confirmed));
    }
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        unsafe {
            TerminateJobObject(job.as_raw_handle(), 1);
        }
        let confirmed =
            unsafe { WaitForSingleObject(process.as_raw_handle(), 3000) } == WAIT_OBJECT_0;
        return Err(("ERESUME", confirmed));
    }
    Ok(Process {
        job,
        process,
        thread,
        stdout,
        stderr,
        pid: info.dwProcessId,
    })
}
fn active(job: &OwnedHandle) -> Option<u32> {
    let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
    (unsafe {
        QueryInformationJobObject(
            job.as_raw_handle(),
            JobObjectBasicAccountingInformation,
            (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of_val(&info) as u32,
            null_mut(),
        )
    } != 0)
        .then_some(info.ActiveProcesses)
}
fn drain(mut pipe: File, stream: &'static str, output: Arc<Output>, readers: Arc<AtomicUsize>) {
    std::thread::spawn(move || {
        let mut bytes = [0; 4096];
        loop {
            match pipe.read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => output.capture(stream, &bytes[..n]),
                Err(_) => {
                    output.failed();
                    break;
                }
            }
        }
        readers.fetch_sub(1, Ordering::Release);
    });
}
pub(super) fn run(
    prepare: &Prepare,
    control: &mpsc::Receiver<Value>,
    output: &Arc<Output>,
    lost: &Arc<AtomicBool>,
) {
    let process = match create(prepare) {
        Ok(process) => process,
        Err((code, confirmed)) => {
            output.finish(None, "failed", confirmed, Some(code));
            return;
        }
    };
    let Process {
        job,
        process,
        thread,
        stdout,
        stderr,
        pid,
    } = process;
    drop(thread);
    output.send(json!({"kind":"started","pid":pid}));
    let readers = Arc::new(AtomicUsize::new(2));
    drain(stdout, "stdout", output.clone(), readers.clone());
    drain(stderr, "stderr", output.clone(), readers.clone());
    let deadline = Instant::now() + Duration::from_millis(prepare.timeout_ms);
    let mut stopping = None;
    let mut reason = "exited";
    let mut error = None;
    let confirmed = loop {
        if active(&job) == Some(0)
            && unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } == WAIT_OBJECT_0
        {
            break true;
        }
        while let Ok(frame) = control.try_recv() {
            if prepare.control(&frame) == Some("cancel") {
                if stopping.is_none() {
                    reason = "cancelled";
                }
            } else {
                reason = "control-lost";
                error = Some("EPROTOCOL");
            }
        }
        if lost.load(Ordering::Acquire) {
            reason = "control-lost";
            error = Some("EPIPE");
        }
        if reason == "exited" && Instant::now() >= deadline {
            reason = "timed-out";
        }
        if active(&job).is_none() {
            reason = "failed";
            error = Some("EJOB");
        }
        if reason != "exited" && stopping.is_none() {
            unsafe {
                TerminateJobObject(job.as_raw_handle(), 1);
            }
            stopping = Some(Instant::now());
        }
        if stopping.is_some_and(|at| at.elapsed() >= Duration::from_secs(3)) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut code = 0;
    let exit =
        if confirmed && unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } != 0 {
            Some(code)
        } else {
            None
        };
    if confirmed {
        let drain_deadline = Instant::now() + Duration::from_secs(1);
        while readers.load(Ordering::Acquire) > 0 && Instant::now() < drain_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        if readers.load(Ordering::Acquire) > 0 {
            error = Some("EOUTPUT");
        }
    }
    drop(process);
    drop(job);
    output.finish(exit, reason, confirmed, error);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_argument_quoting_preserves_embedded_quotes_and_trailing_slashes() {
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote("x\\"), "\"x\\\\\"");
    }
    #[test]
    fn membership_failure_terminates_the_suspended_process_without_resuming() {
        let prepare = Prepare {
            v: 1,
            session: "a".repeat(36),
            request_id: "b".repeat(36),
            input_hash: "c".repeat(64),
            kind: "prepare".into(),
            command: "Start-Sleep -Seconds 60".into(),
            cwd: std::env::temp_dir().to_string_lossy().into(),
            timeout_ms: 100,
        };
        assert!(matches!(
            create_checked(&prepare, |_, _| false),
            Err(("EASSIGN", true))
        ));
    }

    // Test-executable-only fixture, with no production protocol/env hook.
    #[test]
    fn pre_resume_fixture() {
        let Some(marker) = std::env::var_os("CHAT2LOCAL_UNIT_PRE_RESUME_MARKER") else {
            return;
        };
        let prepare = Prepare {
            v: 1,
            session: "a".repeat(36),
            request_id: "b".repeat(36),
            input_hash: "c".repeat(64),
            kind: "prepare".into(),
            command: "Start-Sleep -Seconds 60".into(),
            cwd: std::env::temp_dir().to_string_lossy().into(),
            timeout_ms: 100,
        };
        let _ = create_checked(&prepare, |job, process| {
            assert!(belongs_to_job(job, process));
            let mut flags = 0;
            assert_ne!(unsafe { GetHandleInformation(job, &mut flags) }, 0);
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
            std::fs::write(marker, unsafe { GetProcessId(process) }.to_string()).unwrap();
            std::thread::sleep(Duration::from_secs(30));
            true
        });
    }

    #[test]
    fn helper_death_before_resume_kills_the_already_attached_shell() {
        let marker = std::env::temp_dir().join(format!(
            "c2l-job-before-resume-{}-{}.pid",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut helper = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::tests::pre_resume_fixture",
                "--nocapture",
            ])
            .env("CHAT2LOCAL_UNIT_PRE_RESUME_MARKER", &marker)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !marker.exists() {
            let _ = helper.kill();
            let _ = helper.wait();
            panic!("pre-resume fixture did not start");
        }
        let pid = std::fs::read_to_string(&marker).unwrap().parse().unwrap();
        let shell = owned(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) }).unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(shell.as_raw_handle(), 0) },
            WAIT_TIMEOUT
        );
        helper.kill().unwrap();
        helper.wait().unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(shell.as_raw_handle(), 5000) },
            WAIT_OBJECT_0
        );
        std::fs::remove_file(marker).unwrap();
    }
}
