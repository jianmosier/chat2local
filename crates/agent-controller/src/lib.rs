//! Native local-controller resources. This partial host cannot impersonate a full Agent.
mod bridge;
mod consent;
mod controller;
#[cfg(feature = "fixture")]
pub mod fixture;
mod guide;
mod http;
mod management;
pub mod native;
mod network;
mod network_query;
mod operations;
mod owner;
mod platform;
mod ui;
#[cfg(feature = "fixture")]
pub use platform::Config as PlatformConfig;
mod onboarding;
mod persistence;
mod runtime;
mod setup;
mod sharing;
mod terminal;
mod tools;
mod value;
mod workflow;
mod workflow_value;
use chat2local_js_value_compat::{Document, Value};
use chat2local_native_store::Store;
use runtime::Host;
pub use runtime::run;
use serde_json::json;
use std::path::PathBuf;
#[cfg(feature = "fixture")]
use std::sync::Arc;
pub const NAME: &str = if cfg!(feature = "fixture") {
    "chat2local-native-controller-fixture"
} else {
    "chat2local-native-agent"
};
pub const ROUTES: &[&str] = &[
    "/account-connect",
    "/account-connect/start",
    "/account-connect/choose",
    "/account-connect/status",
    "/account-connect/confirm",
    "/account-connect/resume",
    "/instance-connect",
    "/instance-connect/start",
    "/instance-connect/choose",
    "/instance-connect/status",
    "/instance-connect/confirm",
    "/instance-connect/resume",
    "/connect",
    "/connect/continue",
    "/api/setup/inspect",
    "/api/setup/start",
    "/api/instance/import-invitation",
    "/api/shares/connections",
    "/api/shares/prepare",
    "/api/shares/confirm",
    "/api/shares/status",
    "/api/shares/resume",
    "/api/shares/remove-prepare",
    "/api/shares/remove-confirm",
    "/api/shares/removals",
    "/api/terminal/permissions",
    "/api/terminal/set-permission",
    "/api/root/add",
    "/api/root/set-mode",
    "/api/folder/select",
    "/api/guide",
    "/api/guide/authorize",
    "/api/guide/cancel",
    "/api/guide/session-tools",
    "/api/pick-folder",
    "/api/folder/cancel",
    "/api/folder/browse",
    "/api/startup",
    "/api/management/startup",
    "/api/network/set",
    "/api/network/check",
    "/api/status",
    "/api/approve",
    "/api/pause",
    "/api/root/remove",
    "/api/account-root/remove",
    "/api/shutdown",
    "/api/management/session",
    "/api/management/logout",
];
#[derive(Debug, Clone)]
pub struct Error {
    pub status: u16,
    pub message: String,
}
impl Error {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(503, e.to_string())
    }
}
impl From<chat2local_native_store::Error> for Error {
    fn from(e: chat2local_native_store::Error) -> Self {
        Self::new(503, e.to_string())
    }
}
impl From<chat2local_js_value_compat::Error> for Error {
    fn from(e: chat2local_js_value_compat::Error) -> Self {
        Self::new(400, e.to_string())
    }
}
pub type Result<T> = std::result::Result<T, Error>;
fn random(n: usize) -> Result<String> {
    let mut bytes = vec![0; n];
    openssl::rand::rand_bytes(&mut bytes)
        .map_err(|_| Error::new(503, "OS randomness unavailable."))?;
    Ok(hex::encode(bytes))
}
fn uuid() -> Result<String> {
    let mut bytes = [0u8; 16];
    openssl::rand::rand_bytes(&mut bytes)
        .map_err(|_| Error::new(503, "OS randomness unavailable."))?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let s = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..]
    ))
}
pub fn version() -> serde_json::Value {
    json!({"name":NAME,"fixtureOnly":cfg!(feature="fixture"),"fullAgent":false,"upgradeReady":false,"version":"0.1.0-alpha.29","openssl":openssl::version::version(),"routes":ROUTES,"unsupported":["disconnect","general-enroll","pair-code"],"bridgeTools":["list_devices","list_roots","list_directory","read_file","write_file","propose_write","operation_status","terminal_execute","terminal_status","terminal_cancel"],"terminalAvailable":true,"localPanel":true})
}
pub struct Options {
    pub directory: PathBuf,
    pub port: u16,
    #[cfg(feature = "fixture")]
    pub publication_delay_ms: u64,
    #[cfg(feature = "fixture")]
    pub hooks: Arc<fixture::Hooks>,
    #[cfg(feature = "fixture")]
    pub transport: fixture::TransportConfig,
    #[cfg(feature = "fixture")]
    pub platform: PlatformConfig,
}
impl Options {
    pub fn new(directory: PathBuf, port: u16) -> Self {
        Self {
            directory,
            port,
            #[cfg(feature = "fixture")]
            publication_delay_ms: 0,
            #[cfg(feature = "fixture")]
            hooks: Arc::new(fixture::Hooks::default()),
            #[cfg(feature = "fixture")]
            transport: fixture::TransportConfig::default(),
            #[cfg(feature = "fixture")]
            platform: PlatformConfig::default(),
        }
    }
}
pub struct Ready {
    pub origin: String,
    pub instance_id: String,
    pub port: u16,
    #[cfg(feature = "fixture")]
    pub control: fixture::Control,
}
pub(crate) struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    disconnected: tokio::sync::watch::Receiver<bool>,
    selection: Option<u64>,
}
impl Request {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
}
#[derive(Clone)]
pub(crate) struct Reply {
    content_type: &'static str,
    status: u16,
    body: String,
    cookie: Option<String>,
}
impl Reply {
    fn json(value: serde_json::Value) -> Self {
        Self {
            content_type: "application/json; charset=utf-8",
            status: 200,
            body: value.to_string(),
            cookie: None,
        }
    }
    fn error(e: Error) -> Self {
        Self {
            content_type: "application/json; charset=utf-8",
            status: e.status,
            body: json!({"error":e.message}).to_string(),
            cookie: None,
        }
    }
}
fn root_mode(doc: &Document, id: chat2local_js_value_compat::ValueId) -> Result<String> {
    let write = value::boolean(doc, value::get(doc, id, "write"))
        .ok_or_else(|| Error::new(400, "Invalid directory permission."))?;
    let selected = value::get(doc, id, "writeMode");
    let mode = match selected.map(|id| doc.value(id)).transpose()? {
        None | Some(Value::Null | Value::Undefined) => {
            if write { "review" } else { "read-only" }.to_owned()
        }
        Some(Value::String(_)) => value::string(doc, selected)
            .ok_or_else(|| Error::new(400, "Invalid directory permission."))?,
        _ => return Err(Error::new(400, "Invalid directory permission.")),
    };
    if !["read-only", "review", "direct"].contains(&mode.as_str()) || write != (mode != "read-only")
    {
        return Err(Error::new(400, "Invalid directory permission."));
    }
    Ok(mode)
}
fn validate(config: &Document) -> Result<()> {
    let roots = value::array(config, value::prop(config, "roots"))
        .ok_or_else(|| Error::new(400, "Invalid saved directory permissions."))?;
    let account = match value::prop(config, "accountRoots") {
        None => vec![],
        Some(id) => value::array(config, Some(id))
            .ok_or_else(|| Error::new(400, "Invalid account-scoped directory policy."))?,
    };
    if roots.len() > 50 || account.len() > 100 {
        return Err(Error::new(400, "Too many saved directories."));
    }
    let mut ids = std::collections::HashSet::new();
    for id in roots.into_iter().chain(account) {
        let identity = value::string(config, value::get(config, id, "id"))
            .ok_or_else(|| Error::new(400, "Invalid directory identity."))?;
        if !ids.insert(identity) || value::string(config, value::get(config, id, "path")).is_none()
        {
            return Err(Error::new(
                400,
                "Invalid or duplicate directory permission.",
            ));
        }
        root_mode(config, id)?;
    }
    Ok(())
}
struct Initial {
    store: Store,
    config: Document,
    secrets: Document,
    origin: String,
    token: String,
    instance: String,
    bridge: network::Config,
    platform: std::sync::Arc<platform::Service>,
}
fn startup(options: &Options) -> Result<Initial> {
    let owner = owner::Ownership::claim(&options.directory)?;
    let store = owner.store();
    chat2local_native_store::assert_write_fence_clear(&options.directory)?;
    let loaded = store.load()?;
    validate(&loaded.config)?;
    let mut business = Initial {
        store,
        config: loaded.config,
        secrets: loaded.secrets,
        origin: format!("http://127.0.0.1:{}", options.port),
        token: random(32)?,
        instance: uuid()?,
        bridge: network::Config::new(options)?,
        platform: platform::Service::new(
            #[cfg(feature = "fixture")]
            options.platform.clone(),
        )?,
    };
    // Only fixture builds expose this bounded test hook; no HTTP route can select it.
    #[cfg(feature = "fixture")]
    std::thread::sleep(std::time::Duration::from_millis(
        options.publication_delay_ms.min(5000),
    ));
    if !value::truthy(
        &business.config,
        value::prop(&business.config, "installationId"),
    ) {
        value::put(
            &mut business.config,
            "installationId",
            value::text(&uuid()?),
        )?;
        business.store.save_config(&business.config)?;
    }
    let (created, image) = owner::Ownership::identity()?;
    business.store.save_session(&value::parse(json!({"origin":business.origin,"token":business.token,"instanceId":business.instance,"pid":std::process::id(),"ownerCreated":created,"ownerImage":image,"profile":NAME,"fixtureOnly":cfg!(feature="fixture"),"fullAgent":false,"upgradeReady":false}).to_string().as_bytes())?)?;
    owner.published(&business.instance)?;
    Ok(business)
}
