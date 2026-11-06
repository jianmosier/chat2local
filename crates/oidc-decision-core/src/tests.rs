use super::*;
use serde_json::{Value, json};

fn send(engine: &mut Engine, command: Value) -> Option<Value> {
    let bytes =
        serde_json::to_vec(&json!({"v":1,"serial":engine.serial + 1,"command":command})).unwrap();
    dispatch(engine, &bytes)
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap()["result"].clone())
}
fn pre(engine: &mut Engine) {
    assert_eq!(
        send(
            engine,
            json!({"kind":"callback_pre","counts":[1,1,0,1],"state":vec![97_u16;64]})
        )
        .unwrap()["kind"],
        "cookie"
    );
    assert_eq!(
        send(
            engine,
            json!({"kind":"callback_cookie","cookie":vec![98_u16;64]})
        )
        .unwrap()["kind"],
        "take"
    );
}
fn after(error: bool, length: u64, actual: u64, expected: u64) -> Value {
    json!({"kind":"callback_after_take","has_error":error,"code":{"present":true,"length16":length,"units":if length<=4096 { Some(vec![120_u16;length as usize]) } else { None }},"iss_present":true,"issuer_length16":actual,"expected_length16":expected})
}
fn begin(path: &str, pathname: &str, connections: u64, connection: &str) -> Value {
    json!({"kind":"begin","is_string":true,"length16":path.encode_utf16().count(),"prefix":path.encode_utf16().take(11).collect::<Vec<_>>(),
      "target":{"same_origin":true,"has_hash":false,"pathname_length16":pathname.encode_utf16().count(),"pathname_prefix":pathname.encode_utf16().take(12).collect::<Vec<_>>(),"other_keys":false,"connections":connections,"connection_length16":connection.encode_utf16().count(),"connection":connection.encode_utf16().take(33).collect::<Vec<_>>()}})
}

#[test]
fn begin_authorize_and_join_decisions() {
    for command in [
        begin("/authorize?client_id=x", "/authorize", 0, ""),
        begin("/account/add", "/account/add", 0, ""),
        begin(
            "/account/add?connection=x",
            "/account/add",
            1,
            &"a".repeat(32),
        ),
    ] {
        assert_eq!(
            send(&mut Engine::default(), command).unwrap()["kind"],
            "accepted"
        );
    }
    for command in [
        begin("authorize?x", "/authorize", 0, ""),
        begin("/account/add?connection=x", "/account/add", 1, "x"),
        begin("/account/add", "/account/add/", 0, ""),
        begin("/account/add", "/account/add", 2, &"a".repeat(32)),
        begin(
            &format!("/authorize?{}", "x".repeat(8192)),
            "/authorize",
            0,
            "",
        ),
    ] {
        assert_eq!(
            send(&mut Engine::default(), command).unwrap()["status"],
            400
        );
    }
}

#[test]
fn callback_duplicate_before_state_and_cookie() {
    let result = send(
        &mut Engine::default(),
        json!({"kind":"callback_pre","counts":[0,2,0,0],"state":null}),
    )
    .unwrap();
    assert_eq!(result["message"], "Duplicate identity callback fields.");
    let result = send(
        &mut Engine::default(),
        json!({"kind":"callback_pre","counts":[0,1,0,0],"state":null}),
    )
    .unwrap();
    assert_eq!(result["message"], "Identity callback state is missing.");
}

#[test]
fn cookie_admission_uses_original_parsed_value() {
    for cookie in [Value::Null, json!(vec![65_u16; 64])] {
        let mut engine = Engine::default();
        send(
            &mut engine,
            json!({"kind":"callback_pre","counts":[1,1,0,0],"state":vec![97_u16;64]}),
        );
        assert_eq!(
            send(
                &mut engine,
                json!({"kind":"callback_cookie","cookie":cookie})
            )
            .unwrap()["message"],
            "This sign-in belongs to another browser or has expired."
        );
    }
}

#[test]
fn after_take_rejects_error_empty_oversize_or_different_length() {
    for command in [
        after(true, 1, 10, 10),
        after(false, 0, 10, 10),
        after(false, 4097, 10, 10),
        after(false, 1, 10, 11),
    ] {
        let mut engine = Engine::default();
        pre(&mut engine);
        assert_eq!(send(&mut engine, command).unwrap()["status"], 401);
    }
}

#[test]
fn absent_issuer_accepts_original_code_units() {
    let mut engine = Engine::default();
    pre(&mut engine);
    let mut command = after(false, 2, 0, 100);
    command["iss_present"] = json!(false);
    command["code"]["units"] = json!([0xd800, 0xdc00]);
    assert_eq!(
        send(&mut engine, command).unwrap(),
        json!({"kind":"code_accepted","code":[0xd800,0xdc00]})
    );
}

#[test]
fn chunked_issuer_compares_every_unit_and_retains_code() {
    for matching in [true, false] {
        let mut engine = Engine::default();
        pre(&mut engine);
        assert_eq!(
            send(&mut engine, after(false, 1, 1025, 1025)).unwrap()["kind"],
            "comparing"
        );
        for (offset, length) in [(0, 512), (512, 512), (1024, 1)] {
            let actual = vec![0xd800_u16; length];
            let mut expected = actual.clone();
            if !matching && offset == 512 {
                expected[511] = 0xdc00;
            }
            assert_eq!(send(&mut engine, json!({"kind":"issuer_chunk","offset":offset,"actual":actual,"expected":expected})).unwrap()["offset"], offset + length);
        }
        assert_eq!(
            send(&mut engine, json!({"kind":"issuer_finish"})).unwrap()["kind"],
            if matching {
                "code_accepted"
            } else {
                "rejected"
            }
        );
    }
}

#[test]
fn stage_mistakes_and_wrong_chunk_offsets_poison_instance() {
    let mut engine = Engine::default();
    assert!(send(&mut engine, json!({"kind":"issuer_finish"})).is_none());
    assert!(send(&mut engine, begin("/account/add", "/account/add", 0, "")).is_none());
    for command in [
        json!({"kind":"issuer_finish"}),
        json!({"kind":"issuer_chunk","offset":1,"actual":[97],"expected":[97]}),
    ] {
        let mut engine = Engine::default();
        pre(&mut engine);
        send(&mut engine, after(false, 1, 1, 1));
        assert!(send(&mut engine, command).is_none());
    }
}

#[test]
fn safe_lengths_do_not_allocate_declared_issuer_size() {
    let mut engine = Engine::default();
    pre(&mut engine);
    assert_eq!(
        send(&mut engine, after(false, 1, MAX_SAFE, MAX_SAFE)).unwrap()["total"],
        MAX_SAFE
    );
    assert!(send(&mut engine, json!({"kind":"issuer_finish"})).is_none());
    let mut engine = Engine::default();
    pre(&mut engine);
    assert!(send(&mut engine, after(false, 1, MAX_SAFE + 1, MAX_SAFE + 1)).is_none());
}

#[test]
fn invalid_serial_version_and_frame_are_terminal() {
    for frame in [
        json!({"v":2,"serial":1,"command":{"kind":"issuer_finish"}}),
        json!({"v":1,"serial":0,"command":{"kind":"issuer_finish"}}),
        json!({"v":1,"serial":1,"command":{"kind":"callback_pre","counts":[0,0,0,0],"state":null},"extra":1}),
    ] {
        let mut engine = Engine::default();
        assert!(dispatch(&mut engine, &serde_json::to_vec(&frame).unwrap()).is_none());
        assert!(send(&mut engine, begin("/account/add", "/account/add", 0, "")).is_none());
    }
}
