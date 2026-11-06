use crate::{ErrorCode, Result, Stage, TransportError};
use foreign_types::ForeignTypeRef;
use openssl::{
    nid::Nid,
    ssl::{SslContext, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode, SslVersion},
    x509::{X509, X509Ref, store::X509StoreBuilder, verify::X509VerifyFlags},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, net::IpAddr, sync::Arc};

const ROOTS: &[u8] = include_bytes!("../data/node-24.21.0-roots.pem");
const POLICY: &str = include_str!("../data/node-24.21.0-policy.json");
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsProfile {
    #[default]
    Default,
    ProxyCompatible,
}
/// Immutable startup policy, with explicit built-in roots and optional extra PEM.
/// No Windows/OpenSSL default trust path is loaded implicitly.
#[derive(Clone)]
pub struct StartupTls {
    roots: Arc<Vec<X509>>,
}
fn incompatible() -> TransportError {
    TransportError::new(ErrorCode::IncompatiblePolicy, Stage::Preflight)
}
impl StartupTls {
    pub fn from_environment(env: &BTreeMap<String, String>) -> Result<Self> {
        if !openssl::version::version().starts_with("OpenSSL 3.5.8 ") {
            return Err(incompatible());
        }
        for name in [
            "NODE_USE_SYSTEM_CA",
            "NODE_USE_OPENSSL_CA",
            "OPENSSL_CONF",
            "OPENSSL_MODULES",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NODE_OPENSSL_CERT_STORE",
        ] {
            if env.get(name).is_some_and(|s| {
                !s.is_empty()
                    && !(s == "0" && matches!(name, "NODE_USE_SYSTEM_CA" | "NODE_USE_OPENSSL_CA"))
            }) {
                return Err(incompatible());
            }
        }
        if env
            .get("NODE_TLS_REJECT_UNAUTHORIZED")
            .is_some_and(|s| s == "0")
        {
            return Err(incompatible());
        }
        // Deliberately narrow startup parser; quoting/unknown switches must never
        // silently change TLS or trust semantics. Other native host options can
        // be added when their contract is implemented.
        if let Some(options) = env.get("NODE_OPTIONS") {
            for arg in options.split_whitespace() {
                if !matches!(
                    arg,
                    "--use-bundled-ca" | "--tls-min-v1.2" | "--tls-max-v1.3"
                ) {
                    return Err(incompatible());
                }
            }
        }
        let mut roots = X509::stack_from_pem(ROOTS).map_err(|_| incompatible())?;
        if let Some(path) = env.get("NODE_EXTRA_CA_CERTS").filter(|s| !s.is_empty()) {
            let mut pem = Vec::new();
            std::fs::File::open(path)
                .map_err(|_| incompatible())?
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut pem)
                .map_err(|_| incompatible())?;
            if pem.len() > 8 * 1024 * 1024 {
                return Err(incompatible());
            }
            let extra = X509::stack_from_pem(&pem).map_err(|_| incompatible())?;
            if extra.is_empty() {
                return Err(incompatible());
            }
            roots.extend(extra);
        }
        Ok(Self {
            roots: Arc::new(roots),
        })
    }
    #[cfg(feature = "fixture")]
    pub fn fixture_with_ca(env: &BTreeMap<String, String>, pem: &[u8]) -> Result<Self> {
        let mut tls = Self::from_environment(env)?;
        Arc::make_mut(&mut tls.roots)
            .extend(X509::stack_from_pem(pem).map_err(|_| incompatible())?);
        Ok(tls)
    }
    pub(crate) fn context(&self, profile: TlsProfile) -> Result<SslContext> {
        let mut builder =
            SslContextBuilder::new(SslMethod::tls_client()).map_err(|_| incompatible())?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|_| incompatible())?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| incompatible())?;
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_options(SslOptions::NO_COMPRESSION);
        let policy: serde_json::Value = serde_json::from_str(POLICY).map_err(|_| incompatible())?;
        let ciphers = policy["defaultCiphers"].as_str().ok_or_else(incompatible)?;
        let (modern, legacy): (Vec<_>, Vec<_>) =
            ciphers.split(':').partition(|c| c.starts_with("TLS_"));
        builder
            .set_ciphersuites(&modern.join(":"))
            .map_err(|_| incompatible())?;
        builder
            .set_cipher_list(&legacy.join(":"))
            .map_err(|_| incompatible())?;
        if profile == TlsProfile::ProxyCompatible {
            builder
                .set_groups_list("X25519:P-256")
                .map_err(|_| incompatible())?;
        }
        let mut store = X509StoreBuilder::new().map_err(|_| incompatible())?;
        store
            .set_flags(X509VerifyFlags::TRUSTED_FIRST)
            .map_err(|_| incompatible())?;
        for cert in self.roots.iter() {
            store.add_cert(cert.clone()).map_err(|_| incompatible())?;
        }
        builder.set_cert_store(store.build());
        Ok(builder.build())
    }
}
// Port of Node v24.21.0 lib/tls.js splitHost/check/checkServerIdentity. DER SAN
// access avoids parsing the human-readable, escaped OpenSSL SAN string.
fn unfqdn(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}
fn matches(host: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let pattern = unfqdn(pattern).to_ascii_lowercase();
    let host = unfqdn(host).to_ascii_lowercase();
    let p: Vec<_> = pattern.split('.').collect();
    let h: Vec<_> = host.split('.').collect();
    if p.len() != h.len()
        || p.iter()
            .any(|s| s.is_empty() || s.bytes().any(|b| !(0x21..=0x7f).contains(&b)))
    {
        return false;
    }
    if p.iter().skip(1).ne(h.iter().skip(1)) {
        return false;
    }
    let wild: Vec<_> = p[0].split('*').collect();
    if wild.len() == 1 || p[0].contains("xn--") {
        return p[0] == h[0];
    }
    wild.len() == 2
        && p.len() > 2
        && wild[0].len() + wild[1].len() <= h[0].len()
        && h[0].starts_with(wild[0])
        && h[0].ends_with(wild[1])
}
pub(crate) fn identity(host: &str, cert: &X509Ref) -> bool {
    let host = unfqdn(host);
    let sans = cert.subject_alt_names();
    if let Ok(ip) = host.parse::<IpAddr>() {
        let bytes = match ip {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        };
        return sans.is_some_and(|names| {
            names
                .iter()
                .any(|name| name.ipaddress() == Some(bytes.as_slice()))
        });
    }
    let ascii = match url::Host::parse(host) {
        Ok(url::Host::Domain(h)) => h,
        _ => return false,
    };
    let dns: Vec<_> = sans
        .as_ref()
        .map(|names| names.iter().filter_map(|name| name.dnsname()).collect())
        .unwrap_or_default();
    // dnsname() returns None for invalid UTF8 too. Preserve the ASN.1 tag's
    // presence so malformed DNS SANs cannot enable an otherwise matching CN.
    // SAFETY: each GeneralNameRef is borrowed from the live owned SAN stack;
    // only its public OpenSSL GENERAL_NAME discriminator is read.
    let dns_present = sans.as_ref().is_some_and(|names| {
        names
            .iter()
            .any(|name| unsafe { (*name.as_ptr()).type_ == openssl_sys::GEN_DNS })
    });
    if dns_present {
        return dns.iter().any(|name| matches(&ascii, name));
    }
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .filter_map(|entry| entry.data().to_string().ok())
        .any(|cn| matches(&ascii, &cn))
}
#[cfg(feature = "fixture")]
pub fn fixture_identity(host: &str, pem: &[u8]) -> Result<bool> {
    let cert = X509::from_pem(pem).map_err(|_| incompatible())?;
    Ok(identity(host, &cert))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn node_wildcards() {
        assert!(matches("www.example.test", "w*.example.test"));
        assert!(!matches("a.test", "*.test"));
        assert!(!matches("a.b.example.test", "*.example.test"));
        assert!(matches("EXAMPLE.TEST.", "example.test"));
        assert!(!matches("a.example.test", "*x*.example.test"));
        assert!(!matches("xn--a.example.test", "xn--*.example.test"));
    }
    #[test]
    fn refuses_unknown_startup_trust() {
        for (key, value) in [
            ("NODE_TLS_REJECT_UNAUTHORIZED", "0"),
            ("NODE_OPTIONS", "--use-system-ca"),
            ("SSL_CERT_FILE", "cert.pem"),
            ("NODE_OPTIONS", "--tls-min-v1.1"),
        ] {
            assert!(
                StartupTls::from_environment(&BTreeMap::from([(key.into(), value.into())]))
                    .is_err()
            );
        }
    }
}
