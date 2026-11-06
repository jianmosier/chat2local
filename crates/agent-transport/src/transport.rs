use crate::{
    Consumer, ErrorCode, Result, RoutePlan, SendState, Stage, StartupTls, Target, TlsProfile,
    TransportError, invalid, tls::identity,
};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::{Request, client::conn::http1};
use hyper_util::rt::TokioIo;
use openssl::{
    ssl::{ErrorCode as SslErrorCode, Ssl},
    x509::X509VerifyResult,
};
use serde::Serialize;
use std::{
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::Instant,
};
use tokio_openssl::SslStream;
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{
        client::IntoClientRequest,
        protocol::{Message, WebSocketConfig},
    },
};

trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
type Stream = Box<dyn Duplex>;
type Socket = tokio_tungstenite::WebSocketStream<Stream>;

/// A persistent connection has a bounded handshake and sends, not a lifetime deadline.
pub struct WsSender(Arc<std::sync::Mutex<Socket>>);
pub struct WsReceiver(Arc<std::sync::Mutex<Socket>>);
pub enum WsEvent {
    Text(String),
    Control,
    Closed,
}
fn ws_error(_: impl std::fmt::Display) -> TransportError {
    TransportError::new(ErrorCode::Protocol, Stage::WebSocket)
}
impl WsSender {
    pub async fn ready(&mut self) -> Result<()> {
        tokio::time::timeout(
            Duration::from_secs(5),
            futures_util::future::poll_fn(|cx| {
                let mut socket = self.0.lock().map_err(ws_error)?;
                futures_util::Sink::poll_ready(Pin::new(&mut *socket), cx).map_err(ws_error)
            }),
        )
        .await
        .map_err(|_| TransportError::new(ErrorCode::Timeout, Stage::WebSocket))?
    }
    /// No SplitSink staging slot: this is the underlying WebSocket submission.
    /// The caller holds its authority gate through this synchronous method.
    pub fn start_text(&mut self, text: String) -> Result<()> {
        if text.len() > 512 * 1024 {
            return Err(TransportError::new(ErrorCode::Limit, Stage::WebSocket));
        }
        let mut socket = self.0.lock().map_err(ws_error)?;
        futures_util::Sink::start_send(Pin::new(&mut *socket), Message::Text(text.into()))
            .map_err(ws_error)
    }
    pub async fn flush(&mut self) -> Result<()> {
        tokio::time::timeout(
            Duration::from_secs(5),
            futures_util::future::poll_fn(|cx| {
                let mut socket = self.0.lock().map_err(ws_error)?;
                futures_util::Sink::poll_flush(Pin::new(&mut *socket), cx).map_err(ws_error)
            }),
        )
        .await
        .map_err(|_| TransportError::new(ErrorCode::Timeout, Stage::WebSocket))?
    }
    pub async fn close(&mut self) -> Result<()> {
        tokio::time::timeout(
            Duration::from_secs(1),
            futures_util::future::poll_fn(|cx| {
                let mut socket = self.0.lock().map_err(ws_error)?;
                futures_util::Sink::poll_close(Pin::new(&mut *socket), cx).map_err(ws_error)
            }),
        )
        .await
        .map_err(|_| TransportError::new(ErrorCode::Timeout, Stage::WebSocket))?
    }
}
impl WsReceiver {
    pub async fn receive(&mut self) -> Result<WsEvent> {
        let frame = futures_util::future::poll_fn(|cx| {
            let mut socket = match self.0.lock() {
                Ok(s) => s,
                Err(e) => return std::task::Poll::Ready(Some(Err(ws_error(e)))),
            };
            futures_util::Stream::poll_next(Pin::new(&mut *socket), cx)
                .map(|v| v.map(|r| r.map_err(ws_error)))
        })
        .await;
        match frame {
            Some(Ok(Message::Text(text))) => Ok(WsEvent::Text(text.to_string())),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => Ok(WsEvent::Control),
            None | Some(Ok(Message::Close(_))) => Ok(WsEvent::Closed),
            _ => Err(TransportError::new(ErrorCode::Protocol, Stage::WebSocket)),
        }
    }
}

/// Revisions and close invalidate every outstanding token. Cancellation of one
/// attempt is separate from owner revision, so it cannot cancel a newer attempt.
#[derive(Clone)]
pub struct AttemptOwner {
    revision: watch::Sender<u64>,
    closed: Arc<AtomicBool>,
}
pub struct Attempt {
    revision: u64,
    owner: watch::Receiver<u64>,
    closed: Arc<AtomicBool>,
    cancel: watch::Receiver<bool>,
    cancel_sender: watch::Sender<bool>,
    gate: Option<PublicationGate>,
}
/// Invoke the callback exactly once under the caller's authority guards, or
/// return false without polling it. Never retain the synchronous callback.
pub type PublicationGate = Arc<dyn Fn(&mut dyn FnMut()) -> bool + Send + Sync>;
impl AttemptOwner {
    pub fn new(revision: u64) -> Self {
        Self {
            revision: watch::channel(revision).0,
            closed: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn attempt(&self) -> Attempt {
        let (tx, rx) = watch::channel(false);
        Attempt {
            revision: *self.revision.borrow(),
            owner: self.revision.subscribe(),
            closed: self.closed.clone(),
            cancel: rx,
            cancel_sender: tx,
            gate: None,
        }
    }
    pub fn revise(&self, revision: u64) {
        self.revision.send_replace(revision);
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.revision.send_modify(|r| *r = r.wrapping_add(1));
    }
}
impl Attempt {
    pub fn set_publication_gate(&mut self, gate: PublicationGate) {
        self.gate = Some(gate);
    }
    pub fn cancel_handle(&self) -> watch::Sender<bool> {
        self.cancel_sender.clone()
    }
    fn valid(&self, revision: u64) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) || *self.cancel.borrow() {
            return Err(TransportError::new(ErrorCode::Cancelled, Stage::Lifecycle));
        }
        if revision != self.revision || *self.owner.borrow() != self.revision {
            return Err(TransportError::new(ErrorCode::Stale, Stage::Lifecycle));
        }
        Ok(())
    }
    async fn changed(&mut self) -> TransportError {
        tokio::select! {_ = self.owner.changed()=>TransportError::new(if self.closed.load(Ordering::SeqCst){ErrorCode::Cancelled}else{ErrorCode::Stale},Stage::Lifecycle),_ = self.cancel.changed()=>TransportError::new(ErrorCode::Cancelled,Stage::Lifecycle)}
    }
}
#[derive(Clone, Copy)]
pub struct Limits {
    pub body_bytes: usize,
    pub timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            body_bytes: 512 * 1024,
            timeout: Duration::from_secs(15),
        }
    }
}
pub struct HttpRequest {
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl Default for HttpRequest {
    fn default() -> Self {
        Self {
            method: "GET".into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}
#[derive(Serialize)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub tls_protocol: Option<String>,
    pub proxied: bool,
}
#[derive(Serialize)]
pub struct WsResponse {
    pub text: String,
    pub tls_protocol: Option<String>,
    pub proxied: bool,
}
pub struct WsRequest {
    pub headers: Vec<(String, String)>,
    pub text: String,
}
struct Dialed {
    stream: Stream,
    protocol: Option<String>,
    proxied: bool,
}

#[derive(Clone)]
pub struct Transport {
    tls: StartupTls,
    #[cfg(feature = "fixture")]
    fixture_addresses: Option<Arc<std::collections::BTreeMap<String, std::net::SocketAddr>>>,
}
impl Transport {
    pub fn new(tls: StartupTls) -> Self {
        Self {
            tls,
            #[cfg(feature = "fixture")]
            fixture_addresses: None,
        }
    }
    #[cfg(feature = "fixture")]
    pub fn fixture(
        tls: StartupTls,
        addresses: std::collections::BTreeMap<String, std::net::SocketAddr>,
    ) -> Result<Self> {
        if addresses.values().any(|a| !a.ip().is_loopback()) {
            return Err(invalid());
        }
        Ok(Self {
            tls,
            fixture_addresses: Some(Arc::new(addresses)),
        })
    }
    /// Exercises bytes already delivered after CONNECT without asking an HTTP
    /// parser to accept an unsolicited response before a request was sent.
    #[cfg(feature = "fixture")]
    pub async fn fixture_tunnel_prefix(
        &self,
        plan: &RoutePlan,
        target: &Target,
        length: usize,
        attempt: &mut Attempt,
    ) -> Result<Vec<u8>> {
        if length > 1024 {
            return Err(invalid());
        }
        let sent = AtomicBool::new(false);
        self.bounded(plan, attempt, Limits::default(), &sent, async {
            let mut dialed = self
                .dial(plan, target, Consumer::Business, TlsProfile::Default)
                .await?;
            let mut bytes = vec![0; length];
            dialed
                .stream
                .read_exact(&mut bytes)
                .await
                .map_err(|_| TransportError::new(ErrorCode::Protocol, Stage::Connect))?;
            Ok(bytes)
        })
        .await
    }
    async fn tcp(&self, target: &Target) -> Result<Stream> {
        #[cfg(feature = "fixture")]
        if let Some(addresses) = &self.fixture_addresses {
            let address = addresses
                .get(&target.authority())
                .or_else(|| addresses.get(&target.host))
                .ok_or_else(|| TransportError::new(ErrorCode::Dns, Stage::Dns))?;
            return TcpStream::connect(address)
                .await
                .map(|s| Box::new(s) as Stream)
                .map_err(|e| io_error(&e, Stage::Tcp));
        }
        let addresses = tokio::net::lookup_host((target.host.as_str(), target.port))
            .await
            .map_err(|_| TransportError::new(ErrorCode::Dns, Stage::Dns))?;
        // Address fallback is allowed before HTTP submission; never route fallback.
        let mut last = TransportError::new(ErrorCode::Connect, Stage::Tcp);
        for addr in addresses {
            match TcpStream::connect(addr).await {
                Ok(s) => return Ok(Box::new(s)),
                Err(e) => last = io_error(&e, Stage::Tcp),
            }
        }
        Err(last)
    }
    async fn secure(
        &self,
        stream: Stream,
        target: &Target,
        profile: TlsProfile,
        stage: Stage,
        consumer: Consumer,
    ) -> Result<(Stream, String)> {
        let context = self.tls.context(profile)?;
        let mut ssl = Ssl::new(&context).map_err(|_| TransportError::new(ErrorCode::Tls, stage))?;
        if consumer == Consumer::Business {
            ssl.set_alpn_protos(b"\x08http/1.1")
                .map_err(|_| TransportError::new(ErrorCode::Tls, stage))?;
        }
        if target.host.parse::<IpAddr>().is_err() {
            ssl.set_hostname(&target.host)
                .map_err(|_| TransportError::new(ErrorCode::Tls, stage))?;
        }
        let mut stream =
            SslStream::new(ssl, stream).map_err(|_| TransportError::new(ErrorCode::Tls, stage))?;
        if let Err(error) = Pin::new(&mut stream).connect().await {
            let code = if stream.ssl().verify_result() != X509VerifyResult::OK {
                ErrorCode::Certificate
            } else if error.io_error().is_some_and(|e| {
                matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
                )
            }) || error.code() == SslErrorCode::ZERO_RETURN
                || (error.code() == SslErrorCode::SYSCALL && error.io_error().is_none())
                || error.ssl_error().is_some_and(|stack| {
                    stack
                        .errors()
                        .iter()
                        .any(|e| e.reason() == Some("unexpected eof while reading"))
                })
            {
                ErrorCode::Reset
            } else {
                ErrorCode::Tls
            };
            return Err(TransportError::new(code, stage));
        }
        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| TransportError::new(ErrorCode::Certificate, stage))?;
        if !identity(&target.host, &cert) {
            return Err(TransportError::new(ErrorCode::Hostname, stage));
        }
        let protocol = stream.ssl().version_str().to_string();
        if !matches!(protocol.as_str(), "TLSv1.2" | "TLSv1.3") {
            return Err(TransportError::new(ErrorCode::Tls, stage));
        }
        Ok((Box::new(stream), protocol))
    }
    async fn dial(
        &self,
        plan: &RoutePlan,
        target: &Target,
        consumer: Consumer,
        profile: TlsProfile,
    ) -> Result<Dialed> {
        let proxy = plan.proxy_for(target, consumer)?;
        let mut stream = self.tcp(proxy.map_or(target, |p| &p.target)).await?;
        if let Some(proxy) = proxy {
            if proxy.target.secure() {
                let outer_profile = if proxy.target.host == target.host {
                    profile
                } else {
                    TlsProfile::Default
                };
                (stream, _) = self
                    .secure(
                        stream,
                        &proxy.target,
                        outer_profile,
                        Stage::ProxyTls,
                        consumer,
                    )
                    .await?;
            }
            let authority = target.authority();
            let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
            if let Some(auth) = proxy.authorization(consumer) {
                request.push_str("Proxy-Authorization: ");
                request.push_str(&auth);
                request.push_str("\r\n");
            }
            request.push_str("\r\n");
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|e| io_error(&e, Stage::Connect))?;
            stream
                .flush()
                .await
                .map_err(|e| io_error(&e, Stage::Connect))?;
            // Read exactly through CRLFCRLF. A proxy can coalesce its response
            // with target data: not consuming extra bytes preserves the tunnel.
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                if header.len() >= 8192 {
                    return Err(TransportError::new(ErrorCode::Limit, Stage::Connect));
                }
                header.push(
                    stream
                        .read_u8()
                        .await
                        .map_err(|_| TransportError::new(ErrorCode::Protocol, Stage::Connect))?,
                );
            }
            let text = std::str::from_utf8(&header)
                .map_err(|_| TransportError::new(ErrorCode::Protocol, Stage::Connect))?;
            let status = text.lines().next().unwrap_or("");
            let parts: Vec<_> = status.splitn(3, ' ').collect();
            if parts.len() < 2
                || !matches!(parts[0], "HTTP/1.0" | "HTTP/1.1")
                || parts[1].len() != 3
                || !parts[1].bytes().all(|b| b.is_ascii_digit())
            {
                return Err(TransportError::new(ErrorCode::Protocol, Stage::Connect));
            }
            if parts[1] != "200" {
                return Err(TransportError::new(
                    ErrorCode::ProxyResponse,
                    Stage::Connect,
                ));
            }
            if status.bytes().any(|b| b < 32 || b == 127)
                || text
                    .split("\r\n")
                    .skip(1)
                    .filter(|s| !s.is_empty())
                    .any(|s| {
                        let Some((name, value)) = s.split_once(':') else {
                            return true;
                        };
                        name.is_empty()
                            || !name.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
                            })
                            || value.bytes().any(|b| (b < 32 && b != b'\t') || b == 127)
                    })
            {
                return Err(TransportError::new(ErrorCode::Protocol, Stage::Connect));
            }
        }
        let mut protocol = None;
        if target.secure() {
            let (s, p) = self
                .secure(stream, target, profile, Stage::TargetTls, consumer)
                .await?;
            stream = s;
            protocol = Some(p);
        }
        Ok(Dialed {
            stream,
            protocol,
            proxied: proxy.is_some(),
        })
    }
    async fn bounded<T>(
        &self,
        plan: &RoutePlan,
        attempt: &mut Attempt,
        limits: Limits,
        sent: &AtomicBool,
        operation: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        attempt.valid(plan.revision)?;
        if limits.body_bytes > 512 * 1024
            || limits.timeout.is_zero()
            || limits.timeout > Duration::from_secs(120)
        {
            return Err(invalid());
        }
        let deadline = Instant::now() + limits.timeout;
        let gate = attempt.gate.clone();
        tokio::pin!(operation);
        let operation = std::future::poll_fn(|cx| {
            let mut result = std::task::Poll::Pending;
            let mut poll = || result = operation.as_mut().poll(cx);
            if let Some(gate) = &gate {
                if !gate(&mut poll) {
                    return std::task::Poll::Ready(Err(TransportError::new(
                        ErrorCode::Stale,
                        Stage::Lifecycle,
                    )));
                }
            } else {
                poll();
            }
            result
        });
        // All connection resources and HTTP drivers live in `operation`. Dropping
        // this future closes them here. There is no detached connection task.
        let result = tokio::select! {biased; error=attempt.changed()=>Err(error),_ = tokio::time::sleep_until(deadline)=>Err(TransportError::new(ErrorCode::Timeout,Stage::Lifecycle)),r=operation=>r};
        let result = result.and_then(|value| {
            attempt.valid(plan.revision)?;
            Ok(value)
        });
        result.map_err(|mut e| {
            if sent.load(Ordering::SeqCst) {
                e.send_state = SendState::PossiblySubmitted;
            }
            e
        })
    }
    pub async fn request_once(
        &self,
        plan: &RoutePlan,
        target: &Target,
        profile: TlsProfile,
        request: HttpRequest,
        limits: Limits,
        attempt: &mut Attempt,
    ) -> Result<HttpResponse> {
        if target.websocket() {
            return Err(invalid());
        }
        let sent = AtomicBool::new(false);
        self.bounded(
            plan,
            attempt,
            limits,
            &sent,
            self.request_inner(
                plan,
                target,
                (Consumer::Business, profile),
                request,
                limits,
                &sent,
            ),
        )
        .await
    }
    async fn request_inner(
        &self,
        plan: &RoutePlan,
        target: &Target,
        consumer_profile: (Consumer, TlsProfile),
        request: HttpRequest,
        limits: Limits,
        sent: &AtomicBool,
    ) -> Result<HttpResponse> {
        let (consumer, profile) = consumer_profile;
        let has_response_body = !request.method.eq_ignore_ascii_case("HEAD");
        if request.body.len() > limits.body_bytes {
            return Err(TransportError::new(ErrorCode::Limit, Stage::Preflight));
        }
        let mut builder = Request::builder()
            .method(request.method.as_str())
            .uri(&target.url[url::Position::BeforePath..url::Position::AfterQuery]);
        builder = builder
            .header(
                "Host",
                target.url[url::Position::BeforeHost..url::Position::AfterPort].to_string(),
            )
            .header("Connection", "close");
        for (name, value) in request.headers {
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "proxy-authorization"
                    | "proxy-connection"
                    | "host"
                    | "connection"
                    | "transfer-encoding"
                    | "content-length"
            ) {
                return Err(invalid());
            }
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Full::new(Bytes::from(request.body)))
            .map_err(|_| invalid())?;
        let dialed = self.dial(plan, target, consumer, profile).await?;
        let (mut sender, connection) = http1::Builder::new()
            .max_buf_size(8192)
            .handshake::<_, Full<Bytes>>(TokioIo::new(dialed.stream))
            .await
            .map_err(|_| TransportError::new(ErrorCode::Protocol, Stage::Http))?;
        let work = async {
            sent.store(true, Ordering::SeqCst);
            let response = sender.send_request(request).await.map_err(|error| {
                TransportError::new(
                    if consumer == Consumer::Probe && probe_reset_before_response(&error) {
                        ErrorCode::Reset
                    } else {
                        ErrorCode::Protocol
                    },
                    Stage::Http,
                )
            })?;
            if has_response_body
                && response
                    .headers()
                    .get(hyper::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|n| n > limits.body_bytes as u64)
            {
                return Err(TransportError::new(ErrorCode::Limit, Stage::Http));
            }
            let status = response.status().as_u16();
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame =
                    frame.map_err(|_| TransportError::new(ErrorCode::Protocol, Stage::Http))?;
                if let Ok(data) = frame.into_data() {
                    if data.len() > limits.body_bytes.saturating_sub(bytes.len()) {
                        return Err(TransportError::new(ErrorCode::Limit, Stage::Http));
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            Ok(HttpResponse {
                status,
                body: bytes,
                tls_protocol: dialed.protocol,
                proxied: dialed.proxied,
            })
        };
        tokio::pin!(work);
        tokio::pin!(connection);
        // Poll both in this task. On response completion drop the driver/socket;
        // on driver completion poll ready response once before projecting failure.
        tokio::select! {biased;r=&mut work=>r, _ = &mut connection=>work.await}
    }
    pub async fn select_probe_profile(
        &self,
        plan: &RoutePlan,
        target: &Target,
        attempt: &mut Attempt,
    ) -> Result<TlsProfile> {
        if !target.secure() || target.websocket() {
            return Err(invalid());
        }
        if !plan.has_proxy() {
            attempt.valid(plan.revision)?;
            return Ok(TlsProfile::Default);
        }
        let mut health = target.clone();
        health.url.set_path("/healthz");
        health.url.set_query(None);
        for profile in [TlsProfile::Default, TlsProfile::ProxyCompatible] {
            let sent = AtomicBool::new(false);
            let limits = Limits {
                timeout: Duration::from_millis(3500),
                body_bytes: 512 * 1024,
            };
            let request = HttpRequest {
                method: "HEAD".into(),
                ..HttpRequest::default()
            };
            let result = self
                .bounded(
                    plan,
                    attempt,
                    limits,
                    &sent,
                    self.request_inner(
                        plan,
                        &health,
                        (Consumer::Probe, profile),
                        request,
                        limits,
                        &sent,
                    ),
                )
                .await;
            match result {
                Ok(_) => return Ok(profile),
                Err(e)
                    if profile == TlsProfile::Default
                        && e.code == ErrorCode::Reset
                        && matches!(e.stage, Stage::TargetTls | Stage::ProxyTls | Stage::Http) => {}
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }
    pub async fn websocket_once(
        &self,
        plan: &RoutePlan,
        target: &Target,
        profile: TlsProfile,
        request: WsRequest,
        limits: Limits,
        attempt: &mut Attempt,
    ) -> Result<WsResponse> {
        let WsRequest { headers, text } = request;
        if !target.websocket() {
            return Err(invalid());
        }
        let sent = AtomicBool::new(false);
        let work = async {
            if text.len() > limits.body_bytes {
                return Err(TransportError::new(ErrorCode::Limit, Stage::Preflight));
            }
            let mut request = target
                .url
                .as_str()
                .into_client_request()
                .map_err(|_| invalid())?;
            for (name, value) in headers {
                if matches!(
                    name.to_ascii_lowercase().as_str(),
                    "proxy-authorization"
                        | "proxy-connection"
                        | "host"
                        | "connection"
                        | "upgrade"
                        | "sec-websocket-key"
                        | "sec-websocket-version"
                ) {
                    return Err(invalid());
                }
                request.headers_mut().insert(
                    hyper::header::HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| invalid())?,
                    value.parse().map_err(|_| invalid())?,
                );
            }
            let dialed = self.dial(plan, target, Consumer::Business, profile).await?;
            let config = WebSocketConfig::default()
                .max_message_size(Some(limits.body_bytes))
                .max_frame_size(Some(limits.body_bytes))
                .write_buffer_size(0)
                .max_write_buffer_size(limits.body_bytes + 1024);
            sent.store(true, Ordering::SeqCst);
            let (mut socket, _) = client_async_with_config(request, dialed.stream, Some(config))
                .await
                .map_err(|_| TransportError::new(ErrorCode::Protocol, Stage::WebSocket))?;
            socket
                .send(Message::Text(text.into()))
                .await
                .map_err(|_| TransportError::new(ErrorCode::Protocol, Stage::WebSocket))?;
            for _ in 0..128 {
                match socket.next().await {
                    Some(Ok(Message::Text(text))) => {
                        socket.close(None).await.map_err(|_| {
                            TransportError::new(ErrorCode::Protocol, Stage::WebSocket)
                        })?;
                        return Ok(WsResponse {
                            text: text.to_string(),
                            tls_protocol: dialed.protocol,
                            proxied: dialed.proxied,
                        });
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                        socket.flush().await.map_err(|_| {
                            TransportError::new(ErrorCode::Protocol, Stage::WebSocket)
                        })?;
                    }
                    Some(Err(tokio_tungstenite::tungstenite::Error::Capacity(_))) => {
                        return Err(TransportError::new(ErrorCode::Limit, Stage::WebSocket));
                    }
                    _ => return Err(TransportError::new(ErrorCode::Protocol, Stage::WebSocket)),
                }
            }
            Err(TransportError::new(ErrorCode::Limit, Stage::WebSocket))
        };
        self.bounded(plan, attempt, limits, &sent, work).await
    }
    pub async fn websocket_connect(
        &self,
        plan: &RoutePlan,
        target: &Target,
        profile: TlsProfile,
        headers: Vec<(String, String)>,
        attempt: &mut Attempt,
    ) -> Result<(WsSender, WsReceiver)> {
        if !target.websocket() {
            return Err(invalid());
        }
        let sent = AtomicBool::new(false);
        let work = async {
            let mut request = target
                .url
                .as_str()
                .into_client_request()
                .map_err(|_| invalid())?;
            for (name, value) in headers {
                if matches!(
                    name.to_ascii_lowercase().as_str(),
                    "proxy-authorization"
                        | "proxy-connection"
                        | "host"
                        | "connection"
                        | "upgrade"
                        | "sec-websocket-key"
                        | "sec-websocket-version"
                ) {
                    return Err(invalid());
                }
                request.headers_mut().insert(
                    hyper::header::HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| invalid())?,
                    value.parse().map_err(|_| invalid())?,
                );
            }
            let dialed = self.dial(plan, target, Consumer::Business, profile).await?;
            let config = WebSocketConfig::default()
                .max_message_size(Some(512 * 1024))
                .max_frame_size(Some(512 * 1024))
                .write_buffer_size(0)
                .max_write_buffer_size(512 * 1024 + 1024);
            sent.store(true, Ordering::SeqCst);
            let (socket, response) = client_async_with_config(request, dialed.stream, Some(config))
                .await
                .map_err(ws_error)?;
            if response
                .headers()
                .get_all("sec-websocket-protocol")
                .iter()
                .count()
                != 1
                || response
                    .headers()
                    .get("sec-websocket-protocol")
                    .and_then(|v| v.to_str().ok())
                    != Some("chat2local-v1")
            {
                return Err(TransportError::new(ErrorCode::Protocol, Stage::WebSocket));
            }
            let socket = Arc::new(std::sync::Mutex::new(socket));
            Ok((WsSender(socket.clone()), WsReceiver(socket)))
        };
        self.bounded(plan, attempt, Limits::default(), &sent, work)
            .await
    }
}
// Called only by send_request before hyper delivers any Response. Body-frame
// failures and Business requests cannot enter this probe retry classification.
fn probe_reset_before_response(error: &hyper::Error) -> bool {
    if error.is_parse() || error.is_timeout() {
        return false;
    }
    if error.is_incomplete_message() {
        return true;
    }
    let mut cause = std::error::Error::source(error);
    while let Some(error) = cause {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::ConnectionReset)
        {
            return true;
        }
        cause = error.source();
    }
    false
}
fn io_error(e: &io::Error, stage: Stage) -> TransportError {
    TransportError::new(
        if e.kind() == io::ErrorKind::ConnectionReset {
            ErrorCode::Reset
        } else {
            ErrorCode::Connect
        },
        stage,
    )
}

#[cfg(test)]
mod persistent_tests {
    use super::*;
    use std::task::{Context, Poll};
    #[tokio::test]
    async fn bounded_rechecks_publication_gate_before_resuming_io() {
        for revoked in [false, true] {
            let authority = Arc::new(std::sync::Mutex::new(()));
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let gate_lock = authority.clone();
            let gate_calls = calls.clone();
            let owner = AttemptOwner::new(1);
            let mut attempt = owner.attempt();
            attempt.set_publication_gate(Arc::new(move |poll| {
                let _permission = gate_lock.lock().unwrap();
                if gate_calls.fetch_add(1, Ordering::SeqCst) != 0 && revoked {
                    return false;
                }
                poll();
                true
            }));
            let target = Target::parse("http://127.0.0.1/").unwrap();
            let plan = crate::prepare(
                &crate::NetworkSettings::default(),
                &target,
                &Default::default(),
                None,
                1,
            )
            .unwrap();
            let transport =
                Transport::new(StartupTls::from_environment(&Default::default()).unwrap());
            let submitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut stream = Observed(submitted.clone());
            let mut pending_once = true;
            let work = std::future::poll_fn(|cx| {
                assert!(
                    authority.try_lock().is_err(),
                    "Authority must remain held during the actual I/O poll."
                );
                if pending_once {
                    pending_once = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Pin::new(&mut stream)
                    .poll_write(cx, b"credential")
                    .map(|result| result.map_err(|e| io_error(&e, Stage::Http)))
            });
            let result = transport
                .bounded(
                    &plan,
                    &mut attempt,
                    Limits::default(),
                    &AtomicBool::new(false),
                    work,
                )
                .await;
            assert_eq!(result.is_err(), revoked);
            assert_eq!(
                submitted.load(Ordering::SeqCst),
                if revoked { 0 } else { 10 }
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }
    struct Observed(Arc<std::sync::atomic::AtomicUsize>);
    impl AsyncRead for Observed {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for Observed {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.fetch_add(bytes.len(), Ordering::SeqCst);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn persistent_start_text_submits_without_a_later_flush_or_split_slot() {
        let submitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stream: Stream = Box::new(Observed(submitted.clone()));
        let socket = Socket::from_raw_socket(
            stream,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            Some(WebSocketConfig::default().write_buffer_size(0)),
        )
        .await;
        let mut sender = WsSender(Arc::new(std::sync::Mutex::new(socket)));
        sender.ready().await.unwrap();
        sender.start_text("guarded payload".into()).unwrap();
        // SplitSink would leave this at zero until a later poll_flush outside the gate.
        assert!(submitted.load(Ordering::SeqCst) > 0);
    }
}
