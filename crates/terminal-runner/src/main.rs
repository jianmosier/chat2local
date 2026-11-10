use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

#[cfg(windows)]
mod windows;
const MAX_FRAME: usize = 256 * 1024;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Prepare {
    v: u32,
    session: String,
    request_id: String,
    input_hash: String,
    kind: String,
    command: String,
    cwd: String,
    timeout_ms: u64,
}
impl Prepare {
    fn valid(&self) -> bool {
        let uuid = |s: &str| {
            s.len() == 36
                && s.bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase() || c == b'-')
        };
        self.v == 1
            && self.kind == "prepare"
            && uuid(&self.session)
            && uuid(&self.request_id)
            && self.input_hash.len() == 64
            && self
                .input_hash
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            && !self.command.trim().is_empty()
            && self.command.len() <= 16384
            && !self.command.contains('\0')
            && !self.cwd.is_empty()
            && self.cwd.encode_utf16().count() <= 32760
            && !self.cwd.contains('\0')
            && (100..=300000).contains(&self.timeout_ms)
    }
    fn control(&self, value: &Value) -> Option<&'static str> {
        let object = value.as_object()?;
        if object.len() != 5
            || value["v"] != 1
            || value["session"] != self.session
            || value["requestId"] != self.request_id
            || value["inputHash"] != self.input_hash
        {
            return None;
        }
        match value["kind"].as_str()? {
            "run" => Some("run"),
            "cancel" => Some("cancel"),
            _ => None,
        }
    }
}

fn read_frame(reader: &mut impl BufRead) -> std::io::Result<Option<Value>> {
    let mut bytes = Vec::new();
    (&mut *reader)
        .take((MAX_FRAME + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_FRAME || bytes.last() != Some(&b'\n') {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| std::io::ErrorKind::InvalidData.into())
}

struct OutputState {
    bytes: usize,
    truncated: bool,
    closed: bool,
    sequence: usize,
}
struct Output {
    queue: mpsc::SyncSender<(usize, Value)>,
    written: Arc<AtomicUsize>,
    failed: Arc<AtomicBool>,
    state: Mutex<OutputState>,
    lost: Arc<AtomicBool>,
}
impl Output {
    fn new(binding: Prepare, lost: Arc<AtomicBool>) -> Self {
        let (queue, receiver) = mpsc::sync_channel::<(usize, Value)>(64);
        let written = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicBool::new(false));
        let writer_failed = failed.clone();
        let writer_lost = lost.clone();
        let writer_progress = written.clone();
        std::thread::spawn(move || {
            for (sequence, mut message) in receiver {
                message["v"] = json!(1);
                message["session"] = json!(binding.session);
                message["requestId"] = json!(binding.request_id);
                message["inputHash"] = json!(binding.input_hash);
                let mut bytes = serde_json::to_vec(&message).unwrap();
                bytes.push(b'\n');
                // Only this dispensable I/O thread can wait on the parent pipe.
                // It never holds capture state or any Job/process handle.
                let mut stdout = std::io::stdout().lock();
                if stdout
                    .write_all(&bytes)
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    writer_failed.store(true, Ordering::Release);
                    writer_lost.store(true, Ordering::Release);
                    return;
                }
                writer_progress.store(sequence, Ordering::Release);
            }
        });
        Self {
            queue,
            written,
            failed,
            lost,
            state: Mutex::new(OutputState {
                bytes: 0,
                truncated: false,
                closed: false,
                sequence: 0,
            }),
        }
    }
    fn enqueue(&self, state: &mut OutputState, message: Value) {
        state.sequence += 1;
        if self.queue.try_send((state.sequence, message)).is_err() {
            self.failed.store(true, Ordering::Release);
            self.lost.store(true, Ordering::Release);
        }
    }
    fn failed(&self) {
        self.failed.store(true, Ordering::Release);
        self.lost.store(true, Ordering::Release);
    }
    fn send(&self, message: Value) {
        let mut state = self.state.lock().unwrap();
        if !state.closed {
            self.enqueue(&mut state, message);
        }
    }
    fn capture(&self, stream: &str, bytes: &[u8]) {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return;
        }
        let keep = bytes.len().min(65536 - state.bytes);
        let first_truncation = !state.truncated && keep < bytes.len();
        state.truncated |= keep < bytes.len();
        state.bytes += keep;
        if keep > 0 || first_truncation {
            let truncated = state.truncated;
            self.enqueue(&mut state,json!({"kind":"output","stream":stream,"data":hex::encode(&bytes[..keep]),"truncated":truncated}));
        }
    }
    fn finish(&self, exit_code: Option<u32>, reason: &str, confirmed: bool, code: Option<&str>) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        let truncated = state.truncated || self.failed.load(Ordering::Acquire);
        let code = if self.failed.load(Ordering::Acquire) {
            Some("EOUTPUT")
        } else {
            code
        };
        self.enqueue(&mut state,json!({"kind":"exit","exitCode":exit_code,"reason":reason,"terminationConfirmed":confirmed,"truncated":truncated,"code":code}));
        let sequence = state.sequence;
        drop(state);
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while self.written.load(Ordering::Acquire) < sequence
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn main() {
    #[cfg(feature = "fixture")]
    {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.len() == 2 && args[0] == "--fixture-control-stall-ms" {
            let ms = args[1]
                .parse::<u64>()
                .ok()
                .filter(|n| (1..=10000).contains(n))
                .expect("Bounded owned fixture stall required.");
            std::thread::sleep(Duration::from_millis(ms));
        }
    }
    supervise();
    // Avoid stdio runtime cleanup waiting on an unresponsive parent. All owned
    // Job/process handles were explicitly dropped before returning here.
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Threading::ExitProcess(0);
    }
}
fn supervise() {
    let (sender, receiver) = mpsc::sync_channel(8);
    let lost = Arc::new(AtomicBool::new(false));
    let reader_lost = lost.clone();
    std::thread::spawn(move || {
        let mut reader = std::io::stdin().lock();
        loop {
            match read_frame(&mut reader) {
                Ok(Some(frame)) => {
                    if sender.try_send(frame).is_ok() {
                        continue;
                    }
                    reader_lost.store(true, Ordering::Release);
                    return;
                }
                _ => {
                    reader_lost.store(true, Ordering::Release);
                    return;
                }
            }
        }
    });
    let Ok(value) = receiver.recv_timeout(Duration::from_secs(10)) else {
        return;
    };
    let Ok(prepare) = serde_json::from_value::<Prepare>(value) else {
        return;
    };
    if !prepare.valid() {
        return;
    }
    let output = Arc::new(Output::new(prepare.clone(), lost.clone()));
    output.send(json!({"kind":"ready"}));
    let control = receiver.recv_timeout(Duration::from_secs(10)).ok();
    if lost.load(Ordering::Acquire)
        || control.as_ref().and_then(|v| prepare.control(v)) != Some("run")
    {
        output.finish(None, "failed", true, Some("EACCESS"));
        return;
    }
    #[cfg(windows)]
    windows::run(&prepare, &receiver, &output, &lost);
    #[cfg(not(windows))]
    output.finish(None, "failed", true, Some("ENOTSUP"));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_are_bounded_and_not_partial() {
        assert!(read_frame(&mut &b"{}\n"[..]).unwrap().is_some());
        assert!(read_frame(&mut &b"{}"[..]).is_err());
        assert!(read_frame(&mut &vec![b' '; MAX_FRAME + 1][..]).is_err());
    }
    #[test]
    fn bound_control_is_single_purpose() {
        let p = Prepare {
            v: 1,
            session: "a".repeat(36),
            request_id: "b".repeat(36),
            input_hash: "c".repeat(64),
            kind: "prepare".into(),
            command: "echo test".into(),
            cwd: "C:\\fixture".into(),
            timeout_ms: 100,
        };
        assert!(p.valid());
        let mut v = json!({"v":1,"session":p.session,"requestId":p.request_id,"inputHash":p.input_hash,"kind":"run"});
        assert_eq!(p.control(&v), Some("run"));
        v["inputHash"] = json!("d".repeat(64));
        assert!(p.control(&v).is_none());
    }
    #[test]
    fn dropped_output_is_reported_even_after_the_process_has_exited() {
        let (queue, receiver) = mpsc::sync_channel(1);
        let written = Arc::new(AtomicUsize::new(0));
        let output = Output {
            queue,
            written: written.clone(),
            failed: Arc::new(AtomicBool::new(false)),
            lost: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(OutputState {
                bytes: 0,
                truncated: false,
                closed: false,
                sequence: 0,
            }),
        };
        output.capture("stdout", b"first");
        output.capture("stdout", b"dropped");
        receiver.recv().unwrap();
        let drain = std::thread::spawn(move || {
            let (sequence, receipt) = receiver.recv().unwrap();
            assert_eq!(receipt["code"], "EOUTPUT");
            assert_eq!(receipt["truncated"], true);
            assert_eq!(receipt["terminationConfirmed"], true);
            written.store(sequence, Ordering::Release);
        });
        output.finish(Some(0), "exited", true, None);
        drain.join().unwrap();
    }
}
