use crate::{Result, invalid};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::Ipv4Addr};
use url::{Host, Url};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Consumer {
    Business,
    Probe,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    #[default]
    Auto,
    Direct,
    Proxy,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkSettings {
    pub mode: NetworkMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
}
impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Auto,
            proxy: None,
        }
    }
}

/// URL credentials and fragments are rejected before any dial. Fields stay private.
#[derive(Clone)]
pub struct Target {
    pub(crate) url: Url,
    pub(crate) host: String,
    pub(crate) port: u16,
}
impl Target {
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() > 8192 {
            return Err(invalid());
        }
        let url = Url::parse(value).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "http" | "https" | "ws" | "wss")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        let host = match url.host().ok_or_else(invalid)? {
            Host::Domain(h) => h.to_string(),
            Host::Ipv4(h) => h.to_string(),
            Host::Ipv6(h) => h.to_string(),
        };
        let port = url.port_or_known_default().ok_or_else(invalid)?;
        Ok(Self { url, host, port })
    }
    pub fn secure(&self) -> bool {
        matches!(self.url.scheme(), "https" | "wss")
    }
    pub fn websocket(&self) -> bool {
        matches!(self.url.scheme(), "ws" | "wss")
    }
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
    pub(crate) fn hostname(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }
    pub(crate) fn local(&self) -> bool {
        self.host == "localhost"
            || self.host == "::1"
            || self
                .host
                .parse::<Ipv4Addr>()
                .is_ok_and(|v| v.octets()[0] == 127)
    }
    pub(crate) fn origin(&self) -> String {
        format!(
            "{}://{}",
            if self.secure() { "https" } else { "http" },
            self.authority()
        )
    }
}
#[derive(Clone)]
pub struct Proxy {
    pub(crate) target: Target,
    user: String,
    password: String,
}
impl Proxy {
    pub fn parse(value: &str, credentials: bool) -> Result<Self> {
        if value.is_empty() || value.len() > 2048 {
            return Err(invalid());
        }
        let mut url = Url::parse(value).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || (!credentials
                && (!url.username().is_empty() || url.password().is_some_and(|p| !p.is_empty())))
        {
            return Err(invalid());
        }
        // decodeURIComponent semantics, including malformed percent and strict UTF8.
        let user = decode(url.username())?;
        let password = decode(url.password().unwrap_or(""))?;
        url.set_username("").map_err(|_| invalid())?;
        url.set_password(None).map_err(|_| invalid())?;
        Ok(Self {
            target: Target::parse(url.as_str())?,
            user,
            password,
        })
    }
    pub(crate) fn authorization(&self, c: Consumer) -> Option<String> {
        let enabled = match c {
            Consumer::Business => !self.user.is_empty() && !self.password.is_empty(),
            Consumer::Probe => !self.user.is_empty() || !self.password.is_empty(),
        };
        enabled.then(|| {
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", self.user, self.password))
            )
        })
    }
}
fn decode(s: &str) -> Result<String> {
    let mut bytes = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err(invalid());
            }
            let h = (b[i + 1] as char).to_digit(16).ok_or_else(invalid)?;
            let l = (b[i + 2] as char).to_digit(16).ok_or_else(invalid)?;
            bytes.push((h * 16 + l) as u8);
            i += 3;
        } else {
            bytes.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}
/// Immutable route snapshot. System/PAC decision is an explicit input; this module
/// never reads process environment or queries machine state.
#[derive(Clone)]
pub struct RoutePlan {
    proxy: Option<Proxy>,
    no_proxy: String,
    pub(crate) origin: String,
    pub(crate) revision: u64,
    source: &'static str,
}
impl RoutePlan {
    pub fn proxy_for(&self, target: &Target, c: Consumer) -> Result<Option<&Proxy>> {
        if self.origin != target.origin() {
            return Err(invalid());
        }
        if target.local() || bypass(&target.hostname(), target.port, &self.no_proxy, c) {
            Ok(None)
        } else {
            Ok(self.proxy.as_ref())
        }
    }
    pub fn has_proxy(&self) -> bool {
        self.proxy.is_some()
    }
    pub fn source(&self) -> &'static str {
        self.source
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn same_route(&self, other: &Self) -> bool {
        self.origin == other.origin
            && self.no_proxy == other.no_proxy
            && match (&self.proxy, &other.proxy) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    a.target.url == b.target.url && a.user == b.user && a.password == b.password
                }
                _ => false,
            }
    }
}
fn env<'a>(values: &'a BTreeMap<String, String>, lower: &str, upper: &str) -> &'a str {
    values
        .get(lower)
        .or_else(|| values.get(upper))
        .map(String::as_str)
        .unwrap_or("")
}
fn appended_no_proxy(raw: &str) -> String {
    let mut entries: Vec<&str> = raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect();
    for h in ["127.0.0.1", "localhost", "::1", "[::1]"] {
        if !entries.contains(&h) {
            entries.push(h);
        }
    }
    entries.join(",")
}
pub fn prepare(
    settings: &NetworkSettings,
    target: &Target,
    environment: &BTreeMap<String, String>,
    system_decision: Option<&str>,
    revision: u64,
) -> Result<RoutePlan> {
    let make = |proxy, no_proxy, source| RoutePlan {
        proxy,
        no_proxy,
        source,
        revision,
        origin: target.origin(),
    };
    // Validate manual input even when loopback/direct would otherwise short circuit.
    let manual = if settings.mode == NetworkMode::Proxy {
        Some(Proxy::parse(
            settings.proxy.as_deref().ok_or_else(invalid)?,
            false,
        )?)
    } else {
        None
    };
    if target.local() {
        return Ok(make(None, "*".into(), "loopback"));
    }
    if settings.mode == NetworkMode::Direct {
        return Ok(make(None, "*".into(), "direct"));
    }
    if settings.mode == NetworkMode::Proxy {
        return Ok(make(manual, appended_no_proxy(""), "manual-proxy"));
    }
    let explicit = [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ]
    .iter()
    .any(|k| environment.get(*k).is_some_and(|s| !s.is_empty()));
    let (selected, source) = if explicit {
        let all = env(environment, "all_proxy", "ALL_PROXY");
        let http = env(environment, "http_proxy", "HTTP_PROXY");
        let http = if http.is_empty() { all } else { http };
        let https = env(environment, "https_proxy", "HTTPS_PROXY");
        (
            if target.secure() && !https.is_empty() {
                https
            } else {
                http
            },
            "environment",
        )
    } else {
        let decision = system_decision.ok_or_else(invalid)?;
        (
            decision,
            if decision.is_empty() {
                "system-direct"
            } else {
                "system-proxy"
            },
        )
    };
    let proxy = if selected.is_empty() {
        None
    } else {
        Some(Proxy::parse(selected, true)?)
    };
    let no_proxy = if proxy.is_none() {
        "*".into()
    } else {
        appended_no_proxy(env(environment, "no_proxy", "NO_PROXY"))
    };
    Ok(make(proxy, no_proxy, source))
}
fn suffix(host: &str, pattern: &str) -> bool {
    host == pattern || host.strip_suffix(pattern).is_some_and(|p| p.ends_with('.'))
}
fn bypass(host: &str, port: u16, list: &str, consumer: Consumer) -> bool {
    let host = host.to_ascii_lowercase();
    let list = list.to_ascii_lowercase();
    if consumer == Consumer::Business && list == "*" {
        return true;
    }
    for entry in list.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if consumer == Consumer::Probe {
            if entry == "*" || entry == host || entry == format!("{host}:{port}") {
                return true;
            }
            if let Some(s) = entry.strip_prefix('.')
                && suffix(&host, s)
            {
                return true;
            }
            if let Some(s) = entry.strip_prefix("*.")
                && host != s
                && suffix(&host, s)
            {
                return true;
            }
            if let Ok(h) = host.parse::<Ipv4Addr>() {
                let mut parts = entry.split('-');
                if let (Some(a), Some(b)) = (parts.next(), parts.next())
                    && let (Ok(a), Ok(b)) =
                        (a.trim().parse::<Ipv4Addr>(), b.trim().parse::<Ipv4Addr>())
                    && u32::from(h) >= u32::from(a)
                    && u32::from(h) <= u32::from(b)
                {
                    return true;
                }
            }
        } else {
            let (domain, qualified) = entry
                .rsplit_once(':')
                .filter(|(h, p)| {
                    !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty()
                })
                .map_or((entry, None), |(h, p)| {
                    (h, Some(p.parse::<u64>().unwrap_or(u64::MAX)))
                });
            if qualified.is_some_and(|p| p != 0 && p != u64::from(port)) {
                continue;
            }
            let domain = domain
                .strip_prefix("*.")
                .or_else(|| domain.strip_prefix('.'))
                .unwrap_or(domain);
            if suffix(&host, domain) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consumers_keep_historical_differences() {
        for (entry, b, p) in [
            ("example.test", true, false),
            ("*.example.test", true, true),
            (".example.test", true, true),
            ("*,localhost", false, true),
        ] {
            assert_eq!(bypass("a.example.test", 443, entry, Consumer::Business), b);
            assert_eq!(bypass("a.example.test", 443, entry, Consumer::Probe), p);
        }
        assert!(bypass(
            "example.test",
            443,
            "*.example.test",
            Consumer::Business
        ));
        assert!(!bypass(
            "example.test",
            443,
            "*.example.test",
            Consumer::Probe
        ));
        assert!(bypass(
            "10.0.0.2",
            443,
            "10.0.0.1-10.0.0.3",
            Consumer::Probe
        ));
        assert!(!bypass(
            "10.0.0.2",
            443,
            "10.0.0.1-10.0.0.3",
            Consumer::Business
        ));
    }
    #[test]
    fn strict_credentials_and_loopback() {
        assert!(Proxy::parse("http://bad%FF:x@proxy.test", true).is_err());
        assert!(Proxy::parse("http://bad%:x@proxy.test", true).is_err());
        assert!(
            !Target::parse("https://127.attacker.invalid")
                .unwrap()
                .local()
        );
        assert!(Target::parse("http://127.5.6.7").unwrap().local());
        let p = Proxy::parse("http://a@proxy.test", true).unwrap();
        assert!(p.authorization(Consumer::Business).is_none());
        assert_eq!(p.authorization(Consumer::Probe).unwrap(), "Basic YTo=");
    }
}
