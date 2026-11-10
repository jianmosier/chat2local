use super::*;
fn call(engine: &mut Engine, command: serde_json::Value) -> Option<serde_json::Value> {
    let input = serde_json::to_vec(
        &json!({"v":1,"serial":engine.serial.checked_add(1)?,"command":command}),
    )
    .ok()?;
    serde_json::from_slice(&dispatch(engine, &input)?).ok()
}
fn start() -> serde_json::Value {
    json!({"type":"start","header":"Bearer u:g:secret".encode_utf16().collect::<Vec<_>>(),"resource":"https://relay.test/mcp","url":{"origin":"https://relay.test","pathname":"/mcp","search":""},"scopes":["files:read"]})
}
#[test]
fn sequence_and_type_errors_permanently_poison_request() {
    for response in [
        json!({"type":"resume","sequence":2,"value":{"type":"kv","text":null}}),
        json!({"type":"resume","sequence":1,"value":{"type":"clock","millis":1000}}),
    ] {
        let mut e = Engine::default();
        assert!(call(&mut e, start()).is_some());
        assert!(call(&mut e, response).is_none());
        assert!(call(&mut e, start()).is_none());
    }
}
#[test]
fn original_token_key_and_no_parent_grant_read() {
    let mut e = Engine::default();
    let out = call(&mut e, start()).unwrap();
    let key = out["result"]["op"]["key"].as_str().unwrap();
    assert!(key.starts_with("token:u:g:"));
    assert_eq!(key.len(), 74);
    let out = call(
        &mut e,
        json!({"type":"resume","sequence":1,"value":{"type":"kv","text":null}}),
    )
    .unwrap();
    assert_eq!(out["result"]["kind"], "reject");
    assert!(
        call(
            &mut e,
            json!({"type":"resume","sequence":1,"value":{"type":"kv","text":null}})
        )
        .is_none()
    );
}
#[test]
fn expiry_keeps_javascript_missing_null_and_array_coercion() {
    for (expiry, expired) in [
        ("null", true),
        ("[]", true),
        ("[null]", true),
        ("[\"0x10\"]", true),
        ("[1000]", false),
        ("{}", false),
        ("\"Infinity\"", false),
        ("\"\\u0085\"", false),
        ("\"\\ufeff\"", true),
        ("[1,2]", false),
        ("false", true),
        ("1000", false),
    ] {
        let doc = Document::parse_str(expiry, LIMITS).unwrap();
        assert_eq!(
            number(&doc, Some(doc.root())).unwrap() < 1000.0,
            expired,
            "{expiry}"
        );
    }
    let doc = Document::parse_str("{\"toString\":null}", LIMITS).unwrap();
    assert!(number(&doc, Some(doc.root())).is_err());
}
#[test]
fn base64_uses_forgiving_standard_alphabet() {
    for (source, result) in [
        (" Y Q = =\n", Some(b"a".to_vec())),
        ("YQ", Some(b"a".to_vec())),
        ("YR==", Some(b"a".to_vec())),
        ("YQ=", None),
        ("YQ__", None),
        ("A", None),
    ] {
        assert_eq!(
            base64(&source.encode_utf16().collect::<Vec<_>>()).ok(),
            result
        );
    }
}
#[test]
fn deeply_nested_array_coercion_is_iterative() {
    let depth = 600;
    let source = format!("{}2000000000{}", "[".repeat(depth), "]".repeat(depth));
    let doc = Document::parse_str(&source, LIMITS).unwrap();
    assert_eq!(number(&doc, Some(doc.root())).unwrap(), 2_000_000_000.0);
    let doc = Document::parse_str("[null,[1,null],[\"a\",\"b\"],[]]", LIMITS).unwrap();
    assert_eq!(
        String::from_utf16(&string(&doc, Some(doc.root())).unwrap()).unwrap(),
        ",1,,a,b,"
    );
}
