//! Native, one-attempt outbound transport. No runtime Node, proxy discovery,
//! automatic redirects, replay, system trust mutation, or production selection.
mod policy;
mod tls;
mod transport;

pub use policy::{Consumer, NetworkMode, NetworkSettings, Proxy, RoutePlan, Target, prepare};
#[cfg(feature = "fixture")]
pub use tls::fixture_identity;
pub use tls::{StartupTls, TlsProfile};
pub use transport::{
    Attempt, AttemptOwner, HttpRequest, HttpResponse, Limits, PublicationGate, Transport, WsEvent,
    WsReceiver, WsRequest, WsResponse, WsSender,
};

use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Preflight,
    Dns,
    Tcp,
    ProxyTls,
    Connect,
    TargetTls,
    Http,
    WebSocket,
    Lifecycle,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    IncompatiblePolicy,
    InvalidInput,
    Dns,
    Connect,
    Reset,
    Certificate,
    Hostname,
    Tls,
    ProxyResponse,
    Protocol,
    Limit,
    Timeout,
    Cancelled,
    Stale,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SendState {
    DefinitelyNotSubmitted,
    PossiblySubmitted,
}
/// Intentionally contains no URLs, certificate names, headers, OS messages or secrets.
#[derive(Clone, Debug, Serialize)]
pub struct TransportError {
    pub code: ErrorCode,
    pub stage: Stage,
    pub send_state: SendState,
}
impl TransportError {
    pub(crate) fn new(code: ErrorCode, stage: Stage) -> Self {
        Self {
            code,
            stage,
            send_state: SendState::DefinitelyNotSubmitted,
        }
    }
}
impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native transport {:?} at {:?}", self.code, self.stage)
    }
}
impl std::error::Error for TransportError {}
pub type Result<T> = std::result::Result<T, TransportError>;
pub(crate) fn invalid() -> TransportError {
    TransportError::new(ErrorCode::InvalidInput, Stage::Preflight)
}
