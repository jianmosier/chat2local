//! Bounded local-only development fixture. Never selected by the product host.
use chat2local_agent_transport::{
    AttemptOwner, Consumer, HttpRequest, Limits, NetworkSettings, StartupTls, Target, TlsProfile,
    Transport, WsRequest, fixture_identity, prepare,
};
use openssl::{
    asn1::{Asn1Object, Asn1OctetString, Asn1Time},
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        X509, X509Extension, X509NameBuilder,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    op: String,
    target: Option<String>,
    #[serde(default)]
    settings: NetworkSettings,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    addresses: BTreeMap<String, SocketAddr>,
    ca: Option<String>,
    #[serde(default)]
    profile: TlsProfile,
    #[serde(default)]
    consumer: Option<Consumer>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    method: Option<String>,
    body: Option<String>,
    timeout_ms: Option<u64>,
    body_limit: Option<usize>,
    cancel_ms: Option<u64>,
    revise_ms: Option<u64>,
    close_ms: Option<u64>,
    system: Option<String>,
    host: Option<String>,
    cert: Option<String>,
    issuer_cert: Option<String>,
    issuer_key: Option<String>,
    cn: Option<String>,
    #[serde(default)]
    dns: Vec<String>,
    #[serde(default)]
    ips: Vec<String>,
    not_before: Option<i64>,
    not_after: Option<i64>,
    #[serde(default)]
    malformed_dns: bool,
}
fn certificate(input: &Input) -> std::result::Result<Value, Box<dyn std::error::Error>> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text(
        "CN",
        input
            .cn
            .as_deref()
            .unwrap_or(if input.issuer_cert.is_some() {
                "synthetic-leaf.invalid"
            } else {
                "Synthetic transport CA"
            }),
    )?;
    let name = name.build();
    let issuer = input
        .issuer_cert
        .as_ref()
        .map(|pem| X509::from_pem(pem.as_bytes()))
        .transpose()?;
    let issuer_key = input
        .issuer_key
        .as_ref()
        .map(|pem| PKey::private_key_from_pem(pem.as_bytes()))
        .transpose()?;
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    cert.set_serial_number(&serial)?;
    cert.set_subject_name(&name)?;
    cert.set_issuer_name(issuer.as_ref().map(|c| c.subject_name()).unwrap_or(&name))?;
    cert.set_pubkey(&key)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let before = Asn1Time::from_unix(now + input.not_before.unwrap_or(-60))?;
    let after = Asn1Time::from_unix(now + input.not_after.unwrap_or(86400))?;
    cert.set_not_before(&before)?;
    cert.set_not_after(&after)?;
    if issuer.is_none() {
        cert.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        cert.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
    } else {
        cert.append_extension(BasicConstraints::new().critical().build()?)?;
        cert.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;
        cert.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    }
    if input.malformed_dns {
        let oid = Asn1Object::from_str("2.5.29.17")?;
        let der = Asn1OctetString::new_from_bytes(&[0x30, 3, 0x82, 1, 0xff])?;
        cert.append_extension(X509Extension::new_from_der(&oid, false, &der)?)?;
    } else if !input.dns.is_empty() || !input.ips.is_empty() {
        let mut sans = SubjectAlternativeName::new();
        for dns in &input.dns {
            sans.dns(dns);
        }
        for ip in &input.ips {
            sans.ip(ip);
        }
        let extension = sans.build(&cert.x509v3_context(issuer.as_deref(), None))?;
        cert.append_extension(extension)?;
    }
    let ski = SubjectKeyIdentifier::new().build(&cert.x509v3_context(issuer.as_deref(), None))?;
    cert.append_extension(ski)?;
    if issuer.is_some() {
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&cert.x509v3_context(issuer.as_deref(), None))?;
        cert.append_extension(aki)?;
    }
    cert.sign(issuer_key.as_ref().unwrap_or(&key), MessageDigest::sha256())?;
    // Synthetic private material exists only in this explicit in-memory operation.
    Ok(
        json!({"cert":String::from_utf8(cert.build().to_pem()?)?,"key":String::from_utf8(key.private_key_to_pem_pkcs8()?)?}),
    )
}
fn fixture_error() -> chat2local_agent_transport::TransportError {
    chat2local_agent_transport::TransportError {
        code: chat2local_agent_transport::ErrorCode::InvalidInput,
        stage: chat2local_agent_transport::Stage::Preflight,
        send_state: chat2local_agent_transport::SendState::DefinitelyNotSubmitted,
    }
}
async fn execute(input: Input) -> Value {
    if input.op == "version" {
        return json!({"ok":true,"fixtureOnly":true,"openssl":openssl::version::version(),"drivers":"inline-owned"});
    }
    if input.op == "mint" {
        return match certificate(&input) {
            Ok(v) => json!({"ok":true,"result":v}),
            Err(_) => json!({"ok":false,"error":{"code":"certificate_fixture"}}),
        };
    }
    if input.op == "identity" {
        return match fixture_identity(
            input.host.as_deref().unwrap_or(""),
            input.cert.as_deref().unwrap_or("").as_bytes(),
        ) {
            Ok(v) => json!({"ok":true,"matches":v}),
            Err(e) => json!({"ok":false,"error":e}),
        };
    }
    let result=async {
        let tls=if let Some(ca)=&input.ca {StartupTls::fixture_with_ca(&input.env,ca.as_bytes())?}else{StartupTls::from_environment(&input.env)?};
        if input.op=="policy" {return Ok(json!({"accepted":true}));}
        let target=Target::parse(input.target.as_deref().unwrap_or(""))?;
        let plan=prepare(&input.settings,&target,&input.env,Some(input.system.as_deref().unwrap_or("")),1)?;
        if input.op=="route" {return Ok(json!({"proxied":plan.proxy_for(&target,input.consumer.unwrap_or(Consumer::Business))?.is_some(),"source":plan.source()}));}
        let transport=Transport::fixture(tls,input.addresses)?;
        let owner=AttemptOwner::new(1);let mut attempt=owner.attempt();let cancel=attempt.cancel_handle();
        let limits=Limits{body_bytes:input.body_limit.unwrap_or(512*1024),timeout:Duration::from_millis(input.timeout_ms.unwrap_or(5000))};
        let lifecycle=async {if let Some(ms)=input.cancel_ms{tokio::time::sleep(Duration::from_millis(ms)).await;cancel.send_replace(true);}else if let Some(ms)=input.revise_ms{tokio::time::sleep(Duration::from_millis(ms)).await;owner.revise(2);}else if let Some(ms)=input.close_ms{tokio::time::sleep(Duration::from_millis(ms)).await;owner.close();}else{std::future::pending::<()>().await;}};
        let operation=async {match input.op.as_str(){
            "tunnel_prefix"=>Ok(json!({"bytes":transport.fixture_tunnel_prefix(&plan,&target,input.body_limit.unwrap_or(32),&mut attempt).await?})),
            "http_ws"=>{let http=transport.request_once(&plan,&target,input.profile,HttpRequest::default(),limits,&mut attempt).await?;let ws_url=input.target.as_ref().unwrap().replacen("https:","wss:",1).replacen("http:","ws:",1);let ws_target=Target::parse(&ws_url)?;let ws=transport.websocket_once(&plan,&ws_target,input.profile,WsRequest{headers:Vec::new(),text:"same plan".into()},limits,&mut attempt).await?;Ok(json!({"status":http.status,"text":ws.text,"proxied":ws.proxied}))},
            "request"=>serde_json::to_value(transport.request_once(&plan,&target,input.profile,HttpRequest{method:input.method.unwrap_or_else(||"GET".into()),headers:input.headers,body:input.body.unwrap_or_default().into_bytes()},limits,&mut attempt).await?).map_err(|_|fixture_error()),
            "ws"=>serde_json::to_value(transport.websocket_once(&plan,&target,input.profile,WsRequest{headers:input.headers,text:input.body.unwrap_or_else(||"native exchange".into())},limits,&mut attempt).await?).map_err(|_|fixture_error()),
            "probe"=>Ok(json!({"profile":transport.select_probe_profile(&plan,&target,&mut attempt).await?})),
            _=>Err(fixture_error()),
        }};
        tokio::pin!(operation);tokio::pin!(lifecycle);
        tokio::select!{r=&mut operation=>r,_ = &mut lifecycle=>operation.await}
    }.await;
    match result {
        Ok(v) => json!({"ok":true,"result":v}),
        Err(e) => json!({"ok":false,"error":e}),
    }
}
#[tokio::main]
async fn main() {
    let input = io::stdin();
    let mut reader = input.lock();
    let mut out = io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let mut over = false;
        loop {
            let available = match reader.fill_buf() {
                Ok(v) => v,
                Err(_) => return,
            };
            if available.is_empty() {
                if line.is_empty() {
                    return;
                }
                break;
            }
            let take = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |n| n + 1);
            if line.len() + take > 2 * 1024 * 1024 {
                over = true;
                break;
            }
            line.extend_from_slice(&available[..take]);
            reader.consume(take);
            if line.ends_with(b"\n") {
                break;
            }
        }
        if over {
            let _ = writeln!(
                out,
                "{{\"ok\":false,\"error\":{{\"code\":\"input_limit\"}}}}"
            );
            return;
        }
        let result = match serde_json::from_slice::<Input>(&line) {
            Ok(value) => execute(value).await,
            Err(_) => json!({"ok":false,"error":{"code":"invalid_input"}}),
        };
        if serde_json::to_writer(&mut out, &result).is_err()
            || writeln!(out).is_err()
            || out.flush().is_err()
        {
            return;
        }
    }
}
