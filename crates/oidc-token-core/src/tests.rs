use super::*;
use crate::value::*;
use serde_json::{Value, json};
const FIXTURE: &str = r#"{"token":"eyJhbGciOiJSUzI1NiIsImtpZCI6Imp3ay1mb3JtYXQtc3ludGhldGljIn0.eyJpc3MiOiJodHRwczovL2lkZW50aXR5LmV4YW1wbGUudGVzdCIsImF1ZCI6Imp3ay1mb3JtYXQtY2xpZW50Iiwic3ViIjoic3ludGhldGljLW93bmVyIiwibm9uY2UiOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwiaWF0IjoxNzkzMTUyMzM1LCJleHAiOjE3OTMxNTI2MzUsIm5hbWUiOiJKV0sgZm9ybWF0IGZpeHR1cmUifQ.5E-3zHhCAc4ri0OkzMC03SV3KlqLPh5rT56S6ex34H7o3J0T5i7xdcAZhF_XJ0DF59XsTsuniojDB1rv-hZkJ2yopWw-vO_G-3Fu65EaYno5r3K_uhnBXK8lRpyeDJ_1AIuwH6xfI5ZyAJf6OEbNr8UcSr_gXFZVjp_0QuoO_WnRd0WAmWneNRHGkmqzZLLbMxLOi-2Mtqda9k14uN1A8ll8mXkxXNVUs5iDFcJDUvgiquc4sqUI0l8OaTOM8r4y2NO-wE8wmCk_pm-gNq1fShi4GRCU2fKdS8n0oN2DNL6a2I_wd1JKNunEDc9EwWPmfzOsi7I7MUmRZ50oan6huA","jwks":{"keys":[{"kty":"RSA","n":"7RRLYfgEfxoDFrC-cBm3rsjYb9xsFDlHEGYK4P3-FiJme7FKVKrVB9bqXkt3VD9UGpF0UyONgxH_b1zH1AX1ydqP_s5M1P7NImGFrwcHqlrRnD-MtR0jYx5REdnDZDRXE2qzKlZnVvnc_UTxTGwG8k0loUs2WN4fSNeJSjIfd-v5b9azR11m9-SiZqmHdM7e2_RTH7Cr8P_93OG-sEQmuAGwXl6nIaBJfKq8_lXUtCbrdedySQEHJ02mONvRsuFusM92TEkPGe_ubW5M9Z_RDSE0fqBUQ-wmK8PeQYh6VS5oiWe_R1IGl8fbY2-_QC6etyc0CNB_m5iWgyGJO_8-VQ","e":"AQAB","kid":"jwk-format-synthetic","alg":"RS256","use":"sig"}]},"options":{"issuer":"https://identity.example.test","clientId":"jwk-format-client","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","now":1793152335477,"accessToken":"synthetic-access-only"}}"#;
fn scalar(s: &str) -> Value {
    json!({"type":"string","units":s.encode_utf16().collect::<Vec<_>>()})
}
fn packet() -> Value {
    let f: Value = serde_json::from_str(FIXTURE).unwrap();
    json!({"token":scalar(f["token"].as_str().unwrap()),"jwks":f["jwks"].to_string().encode_utf16().collect::<Vec<_>>(),"issuer":scalar(f["options"]["issuer"].as_str().unwrap()),"client_id":scalar(f["options"]["clientId"].as_str().unwrap()),"nonce":scalar(f["options"]["nonce"].as_str().unwrap()),"access":scalar("access"),"now":{"type":"number","bits":format!("{:016x}",f["options"]["now"].as_f64().unwrap().to_bits())}})
}
fn send(e: &mut Engine, c: Value) -> Option<Value> {
    let b = serde_json::to_vec(&json!({"v":1,"serial":e.serial+1,"command":c})).unwrap();
    dispatch(e, &b).map(|b| serde_json::from_slice::<Value>(&b).unwrap()["result"].clone())
}
fn upload(e: &mut Engine, p: Value) -> Value {
    let b = serde_json::to_vec(&p).unwrap();
    assert_eq!(
        send(e, json!({"kind":"start","length":b.len()})).unwrap()["kind"],
        "upload"
    );
    for (offset, part) in b.chunks(8192).enumerate() {
        send(e, json!({"kind":"chunk","offset":offset*8192,"bytes":part})).unwrap();
    }
    send(e, json!({"kind":"eof"})).unwrap()
}
#[test]
fn standard_public_rs256_vector() {
    let mut e = Engine::default();
    let p = packet();
    let b = p["now"]["bits"].clone();
    assert_eq!(upload(&mut e, p)["kind"], "url");
    assert_eq!(
        send(&mut e, json!({"kind":"skew","bits":b})).unwrap()["kind"],
        "clock"
    );
    let ready = send(&mut e, json!({"kind":"claims","bits":b})).unwrap();
    assert_eq!(ready["kind"], "output");
    let mut out = Vec::new();
    loop {
        let part = send(&mut e, json!({"kind":"output","offset":out.len()})).unwrap();
        out.extend(
            part["bytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_u64().unwrap() as u8),
        );
        if part["eof"] == true {
            break;
        }
    }
    let r: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(r["kind"], "identity");
    assert_eq!(
        r["subject"],
        json!("synthetic-owner".encode_utf16().collect::<Vec<_>>())
    );
}
#[test]
fn corrupt_signature_fails_standard_verifier() {
    let mut p = packet();
    let s = p["token"]["units"].as_array_mut().unwrap();
    let i = s.len() - 20;
    s[i] = json!(if s[i] == 65 { 66 } else { 65 });
    let mut e = Engine::default();
    let b = p["now"]["bits"].clone();
    upload(&mut e, p);
    send(&mut e, json!({"kind":"skew","bits":b}));
    assert_eq!(
        send(&mut e, json!({"kind":"claims","bits":b})).unwrap()["message"],
        "Identity token signature or claims did not verify."
    );
}
#[test]
fn stream_offset_eof_serial_and_stage_fail_closed() {
    for c in [
        json!({"kind":"eof"}),
        json!({"kind":"chunk","offset":0,"bytes":[1]}),
    ] {
        assert!(send(&mut Engine::default(), c).is_none());
    }
    let mut e = Engine::default();
    send(&mut e, json!({"kind":"start","length":10}));
    assert!(send(&mut e, json!({"kind":"chunk","offset":1,"bytes":[1]})).is_none());
    assert!(send(&mut e, json!({"kind":"start","length":0})).is_none());
}
#[test]
fn resource_limit_is_unavailable() {
    assert_eq!(
        send(
            &mut Engine::default(),
            json!({"kind":"start","length":MAX_WIRE+1})
        )
        .unwrap()["kind"],
        "unavailable"
    );
}
#[test]
fn distinct_base64_profiles_preserve_loose_tail_bits() {
    assert_eq!(base64(&[65, 66], 0), Some(vec![0]));
    assert_eq!(base64(&[65, 66, 61, 61], 0), None);
    assert_eq!(base64(&[32, 65, 66, 61, 61, 10], 1), Some(vec![0]));
    assert_eq!(base64(&[65, 65, 11], 1), None);
}
#[test]
fn raw_json_infinity_duplicates_and_normalized_second_view() {
    let d = parse(&r#"{"x":1,"x":1e400}"#.encode_utf16().collect::<Vec<_>>()).unwrap();
    assert_eq!(
        num(&d, prop(&d, d.root(), "x").unwrap()),
        Some(f64::INFINITY)
    );
    assert_eq!(d.stringify(LIMITS).unwrap().unwrap(), r#"{"x":null}"#);
}
#[test]
fn null_raw_key_reconstructs_original_native_error() {
    let mut p = packet();
    p["jwks"] = json!(r#"{"keys":[null]}"#.encode_utf16().collect::<Vec<_>>());
    assert_eq!(
        upload(&mut Engine::default(), p),
        json!({"kind":"native","property":"kid"})
    );
}
#[test]
fn dom_string_nested_arrays_and_noncallable_methods() {
    let d = parse(&r#"[["AQAB"],{"toString":null}]"#.encode_utf16().collect::<Vec<_>>()).unwrap();
    let a = array(&d, d.root()).unwrap();
    assert_eq!(dom_string(&d, a[0]), Some("AQAB".encode_utf16().collect()));
    assert!(dom_string(&d, a[1]).is_none());
}
