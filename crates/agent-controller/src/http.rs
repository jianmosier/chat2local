//! Bounded raw admission before Hyper. Receipt deadlines never time business work.
use crate::{Error, Host, Reply, Request, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout_at},
};
const BODY: usize = 524288;
const SECURITY: [&str; 8] = [
    "host",
    "origin",
    "x-chat2local-token",
    "x-chat2local-manager",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-user",
];
fn bad() -> Error {
    Error::new(400, "Invalid HTTP framing.")
}
async fn byte(input: &mut BufReader<TcpStream>, deadline: Instant) -> Result<u8> {
    timeout_at(deadline, input.read_u8())
        .await
        .map_err(|_| Error::new(408, "Request receipt timed out."))?
        .map_err(Into::into)
}
// Leading header OWS does not count in Node's 8192-byte limit. Discard it while
// reading, so arbitrarily long valid OWS cannot force an unbounded allocation.
async fn line(
    input: &mut BufReader<TcpStream>,
    deadline: Instant,
    header: bool,
    account: &mut usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut after_colon = false;
    let mut leading = true;
    loop {
        let b = byte(input, deadline).await?;
        if b == b'\r' {
            if byte(input, deadline).await? != b'\n' {
                return Err(bad());
            }
            break;
        }
        if b == b'\n' || b == 0 {
            return Err(bad());
        }
        if header && after_colon && leading && (b == b' ' || b == b'\t') {
            continue;
        }
        if header {
            if b == b':' && !after_colon {
                after_colon = true;
            } else {
                *account += 1;
                if after_colon {
                    leading = false;
                }
                if *account >= 8192 {
                    return Err(Error::new(431, "Request headers too large."));
                }
            }
        }
        out.push(b);
        if out.len() > 16384 {
            return Err(Error::new(431, "Request headers too large."));
        }
    }
    Ok(out)
}
struct Raw {
    bytes: Vec<u8>,
    close: bool,
}
async fn read(input: &mut BufReader<TcpStream>, fresh: bool) -> Result<Option<Raw>> {
    // Keepalive starts after the previous response; fresh headers get their own receipt clock.
    let first = match timeout_at(
        Instant::now() + Duration::from_secs(if fresh { 10 } else { 3 }),
        input.fill_buf(),
    )
    .await
    {
        Err(_) => return Ok(None),
        Ok(v) => v?,
    };
    if first.is_empty() {
        return Ok(None);
    }
    let start = Instant::now();
    let header_deadline = start + Duration::from_secs(10);
    let receipt = start + Duration::from_secs(15);
    let mut accounted = 0;
    let request_line = line(input, header_deadline, false, &mut accounted).await?;
    let parts = request_line.split(|b| *b == b' ').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|v| v.is_empty()) {
        return Err(bad());
    }
    accounted = parts[1].len();
    if accounted >= 8192 {
        return Err(Error::new(431, "Request headers too large."));
    }
    let mut bytes = request_line.clone();
    bytes.extend_from_slice(b"\r\n");
    let mut headers = Vec::new();
    let mut seen = std::collections::HashSet::new();
    loop {
        let item = line(input, header_deadline, true, &mut accounted).await?;
        if item.is_empty() {
            break;
        }
        let split = item.iter().position(|b| *b == b':').ok_or_else(bad)?;
        let name = std::str::from_utf8(&item[..split])
            .map_err(|_| bad())?
            .to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err(bad());
        }
        if (SECURITY.contains(&name.as_str())
            || ["content-length", "transfer-encoding"].contains(&name.as_str()))
            && !seen.insert(name.clone())
        {
            return Err(bad());
        }
        let value = std::str::from_utf8(&item[split + 1..])
            .map_err(|_| bad())?
            .trim_matches([' ', '\t'])
            .to_owned();
        headers.push((name, value));
        bytes.extend_from_slice(&item);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    let get = |key: &str| {
        headers
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let length = get("content-length");
    let transfer = get("transfer-encoding");
    let expect = get("expect");
    if !length.is_empty() && !transfer.is_empty() {
        return Err(bad());
    }
    let count = if !length.is_empty() {
        if !length.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        Some(
            length
                .parse::<usize>()
                .map_err(|_| Error::new(413, "Request too large."))?,
        )
    } else {
        None
    };
    if count.is_some_and(|n| n > BODY) {
        return Err(Error::new(413, "Request too large."));
    }
    if !transfer.is_empty() && !transfer.eq_ignore_ascii_case("chunked") {
        return Err(bad());
    }
    if !expect.is_empty() {
        if !expect.eq_ignore_ascii_case("100-continue") {
            return Err(Error::new(417, "Expectation failed."));
        }
        input
            .get_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await?;
    }
    if let Some(count) = count {
        let offset = bytes.len();
        bytes.resize(offset + count, 0);
        timeout_at(receipt, input.read_exact(&mut bytes[offset..]))
            .await
            .map_err(|_| Error::new(408, "Request receipt timed out."))??;
    } else if !transfer.is_empty() {
        let mut total: usize = 0;
        let mut overhead = 0;
        loop {
            let chunk = line(input, receipt, false, &mut 0).await?;
            overhead += chunk.len() + 2;
            if overhead > BODY * 8 {
                return Err(bad());
            }
            let digits = chunk.split(|b| *b == b';').next().unwrap();
            if digits.is_empty() || !digits.iter().all(u8::is_ascii_hexdigit) {
                return Err(bad());
            }
            let size = usize::from_str_radix(std::str::from_utf8(digits).map_err(|_| bad())?, 16)
                .map_err(|_| Error::new(413, "Request too large."))?;
            total = total
                .checked_add(size)
                .ok_or_else(|| Error::new(413, "Request too large."))?;
            if total > BODY {
                return Err(Error::new(413, "Request too large."));
            }
            bytes.extend_from_slice(&chunk);
            bytes.extend_from_slice(b"\r\n");
            if size == 0 {
                let mut trailer_bytes = 0;
                loop {
                    let trailer = line(input, receipt, true, &mut trailer_bytes).await?;
                    if !trailer.is_empty() {
                        let colon = trailer.iter().position(|b| *b == b':').ok_or_else(bad)?;
                        let name = std::str::from_utf8(&trailer[..colon])
                            .map_err(|_| bad())?
                            .to_ascii_lowercase();
                        if SECURITY.contains(&name.as_str())
                            || ["content-length", "transfer-encoding", "cookie"]
                                .contains(&name.as_str())
                        {
                            return Err(bad());
                        }
                    }
                    bytes.extend_from_slice(&trailer);
                    bytes.extend_from_slice(b"\r\n");
                    if trailer.is_empty() {
                        break;
                    }
                }
                break;
            }
            let offset = bytes.len();
            bytes.resize(offset + size + 2, 0);
            timeout_at(receipt, input.read_exact(&mut bytes[offset..]))
                .await
                .map_err(|_| Error::new(408, "Request receipt timed out."))??;
            if &bytes[bytes.len() - 2..] != b"\r\n" {
                return Err(bad());
            }
        }
    }
    Ok(Some(Raw {
        bytes,
        close: parts[2] != b"HTTP/1.1"
            || get("connection")
                .split(',')
                .any(|s| s.trim().eq_ignore_ascii_case("close")),
    }))
}
fn response(reply: Reply) -> Response<Full<Bytes>> {
    let mut builder=Response::builder().status(reply.status).header("Content-Type",reply.content_type).header("Cache-Control","no-store").header("X-Content-Type-Options","nosniff").header("Referrer-Policy","no-referrer").header("X-Frame-Options","DENY").header("Cross-Origin-Opener-Policy","same-origin").header("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    if let Some(cookie) = reply.cookie {
        builder = builder.header("Set-Cookie", cookie);
    }
    builder.body(Full::new(Bytes::from(reply.body))).unwrap()
}
async fn validate_and_dispatch(
    raw: Vec<u8>,
    host: Arc<Host>,
    disconnected: tokio::sync::watch::Receiver<bool>,
) -> Result<Vec<u8>> {
    let (wire, server) = tokio::io::duplex(65536);
    let (mut reader, mut writer) = tokio::io::split(wire);
    let write = tokio::spawn(async move {
        writer.write_all(&raw).await?;
        writer.shutdown().await
    });
    let connection = tokio::spawn(async move {
        http1::Builder::new()
            .keep_alive(false)
            .half_close(true)
            .max_headers(4096)
            .max_buf_size(65536)
            .serve_connection(
                TokioIo::new(server),
                service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let host = host.clone();
                    let disconnected = disconnected.clone();
                    async move {
                        let (parts, body) = request.into_parts();
                        let mut collected = Vec::new();
                        let mut body = body;
                        while let Some(frame) = body.frame().await {
                            match frame {
                                Ok(frame) => {
                                    if let Some(data) = frame.data_ref() {
                                        if collected.len() + data.len() > BODY {
                                            return Ok::<_, std::convert::Infallible>(response(
                                                Reply::error(Error::new(413, "Request too large.")),
                                            ));
                                        }
                                        collected.extend_from_slice(data);
                                    }
                                }
                                Err(_) => return Ok(response(Reply::error(bad()))),
                            }
                        }
                        let mut headers = Vec::<(String, String)>::new();
                        for (name, value) in &parts.headers {
                            let Ok(value) = value.to_str() else {
                                return Ok(response(Reply::error(bad())));
                            };
                            if let Some((_, previous)) =
                                headers.iter_mut().find(|(key, _)| key == name.as_str())
                            {
                                previous.push_str(if name == "cookie" { "; " } else { ", " });
                                previous.push_str(value);
                            } else {
                                headers.push((name.to_string(), value.to_owned()));
                            }
                        }
                        Ok(response(
                            host.dispatch(Request {
                                selection: None,
                                method: parts.method.to_string(),
                                target: parts.uri.to_string(),
                                headers,
                                body: collected,
                                disconnected,
                            })
                            .await,
                        ))
                    }
                }),
            )
            .await
    });
    let mut output = Vec::new();
    reader.read_to_end(&mut output).await?;
    let _ = write.await;
    let parsed = connection.await.map_err(|_| bad())?;
    if parsed.is_err() && output.is_empty() {
        return Err(bad());
    }
    Ok(output)
}
async fn connection(socket: TcpStream, host: Arc<Host>) -> Result<()> {
    let mut input = BufReader::new(socket);
    let mut fresh = true;
    loop {
        if !host.active.load(Ordering::SeqCst) {
            break;
        }
        let raw = match read(&mut input, fresh).await {
            Ok(Some(v)) => v,
            Ok(None) => break,
            Err(e) => {
                let status = e.status;
                let body = serde_json::json!({"error":e.message}).to_string();
                let text = format!(
                    "HTTP/1.1 {status} Error\r\nConnection: close\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = input.get_mut().write_all(text.as_bytes()).await;
                break;
            }
        };
        fresh = false;
        let (cancel, disconnected) = tokio::sync::watch::channel(false);
        let operation = validate_and_dispatch(raw.bytes, host.clone(), disconnected);
        tokio::pin!(operation);
        let mut output = loop {
            tokio::select! {
                result=&mut operation=>break result?,
                _=tokio::time::sleep(Duration::from_millis(50))=>{
                    // Peek never consumes a pipelined request. Detect EOF/error while a
                    // human picker is pending, without cancelling admitted disk work.
                    let mut byte=[0];
                    match input.get_ref().try_io(tokio::io::Interest::READABLE,|| {
                        use std::os::windows::io::{AsRawSocket,FromRawSocket};
                        let socket=std::mem::ManuallyDrop::new(unsafe {std::net::TcpStream::from_raw_socket(input.get_ref().as_raw_socket())});
                        socket.peek(&mut byte)
                    }) {Ok(0) if !cancel.send_replace(true)=>{ #[cfg(feature="fixture")] host.hooks.request_disconnected(); },Err(e) if e.kind()!=std::io::ErrorKind::WouldBlock && !cancel.send_replace(true)=>{ #[cfg(feature="fixture")] host.hooks.request_disconnected(); },_=>{}}
                }
            }
        };
        // Hyper validates one complete request at a time. The outer connection
        // owns pipeline/keepalive lifetime and removes only Hyper's forced close.
        if !raw.close
            && host.active.load(Ordering::SeqCst)
            && let Some(end) = output.windows(4).position(|x| x == b"\r\n\r\n")
        {
            let head = String::from_utf8_lossy(&output[..end])
                .lines()
                .filter(|line| !line.to_ascii_lowercase().starts_with("connection:"))
                .collect::<Vec<_>>()
                .join("\r\n");
            let mut next = head.into_bytes();
            next.extend_from_slice(&output[end..]);
            output = next;
        }
        input.get_mut().write_all(&output).await?;
        if raw.close {
            break;
        }
    }
    Ok(())
}
pub struct Admission {
    pub host: std::sync::Mutex<std::sync::Weak<Host>>,
    pub closed: std::sync::atomic::AtomicBool,
    pub stopped: Arc<tokio::sync::Notify>,
}
impl Admission {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            host: std::sync::Mutex::new(std::sync::Weak::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
            stopped: Arc::new(tokio::sync::Notify::new()),
        })
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.stopped.notify_one();
    }
}
pub async fn serve(listener: &TcpListener, admission: Arc<Admission>) -> Result<()> {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        if admission.closed.load(Ordering::SeqCst) {
            break;
        }
        tokio::select! {biased;
            _=admission.stopped.notified()=>break,
            Some(_)=connections.join_next(),if !connections.is_empty()=>{},
            accepted=listener.accept()=>{let (mut socket,_)=accepted?;if connections.len()>=32{drop(socket);continue;}
                let host=admission.host.lock().unwrap().upgrade().filter(|host|host.active.load(Ordering::SeqCst));
                if host.is_none() {
                    connections.spawn(async move {
                        let _ = tokio::time::timeout(Duration::from_secs(1), async {
                            socket.write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\nCache-Control: no-store\r\n\r\n").await?;
                            socket.shutdown().await?;
                            // Windows can reset a socket dropped with unread request bytes.
                            // Half-close the response, then discard bounded input without admission.
                            let mut discard = [0; 4096];
                            while socket.read(&mut discard).await? != 0 {}
                            Ok::<(), std::io::Error>(())
                        }).await;
                    });
                    continue;
                }
                let host=host.unwrap();connections.spawn(async move {let _=connection(socket,host).await;});}
        }
    }
    // The listener remains reserved through every actual body/FIFO/persistence task.
    while connections.join_next().await.is_some() {}
    Ok(())
}
