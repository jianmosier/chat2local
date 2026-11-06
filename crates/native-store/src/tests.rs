use super::*;
#[test]
fn pretty_preserves_json_bytes_and_order() {
    let doc = json("{\"x\":\"中文😀\",\"a\":[1,{},[]],\"0\":-0}".as_bytes()).unwrap();
    assert_eq!(
        codec::pretty(&compact(&doc).unwrap()),
        "{\n  \"0\": 0,\n  \"x\": \"中文😀\",\n  \"a\": [\n    1,\n    {},\n    []\n  ]\n}"
    );
}
#[test]
fn base64_keeps_windows_and_posix_decode_differences() {
    assert_eq!(codec::encode(b"foobar"), "Zm9vYmFy");
    assert_eq!(
        codec::decode(&"Z m9v\r\n".encode_utf16().collect::<Vec<_>>(), true).unwrap(),
        b"foo"
    );
    assert!(codec::decode(&"Zm9v!".encode_utf16().collect::<Vec<_>>(), true).is_err());
    assert_eq!(
        codec::decode(&"Zm9v!".encode_utf16().collect::<Vec<_>>(), false).unwrap(),
        b"foo"
    );
    for n in 0..20 {
        let bytes = vec![254; n];
        assert_eq!(
            codec::decode(
                &codec::encode(&bytes).encode_utf16().collect::<Vec<_>>(),
                true
            )
            .unwrap(),
            bytes
        );
    }
}

#[test]
fn posix_envelope_bytes_and_replacement_are_platform_independent() {
    let bytes = b"{\"unknown\":\"\xff\",\"2\":1,\"a\":-0}";
    let envelope = codec::envelope("posix-permissions-only", bytes).unwrap();
    let record: serde_json::Value = serde_json::from_str(&compact(&envelope).unwrap()).unwrap();
    let format: Vec<_> = record["format"].as_str().unwrap().encode_utf16().collect();
    let data: Vec<_> = record["data"].as_str().unwrap().encode_utf16().collect();
    assert_eq!(codec::posix_payload(&format, &data).unwrap(), bytes);
    assert_eq!(
        compact(&json(&codec::posix_payload(&format, &data).unwrap()).unwrap()).unwrap(),
        "{\"2\":1,\"unknown\":\"�\",\"a\":0}"
    );
    assert!(
        codec::posix_payload(
            &"windows-dpapi-v1".encode_utf16().collect::<Vec<_>>(),
            &data
        )
        .is_err()
    );
    #[cfg(windows)]
    assert!(codec::unseal(&envelope).is_err());
}
#[test]
fn private_keys_and_truthiness_match_legacy() {
    let store = Store::new("unused");
    assert!(
        store
            .private_record_path("terminal-00000000-0000-0000-0000-000000000000")
            .is_ok()
    );
    for invalid in [
        "terminal-FFFFFFFF-0000-0000-0000-000000000000",
        "../vault",
        "onboarding-flow-0",
    ] {
        assert!(store.private_record_path(invalid).is_err());
    }
    for text in ["null", "false", "0", "\"\""] {
        assert!(!truthy(&json(text.as_bytes()).unwrap()).unwrap());
    }
    for text in ["{}", "[]", "1", "\"false\""] {
        assert!(truthy(&json(text.as_bytes()).unwrap()).unwrap());
    }
}
#[test]
fn utf8_replacement_and_invalid_settings_never_default() {
    assert_eq!(compact(&json(b"\"a\xffb\"").unwrap()).unwrap(), "\"a�b\"");
    for text in [
        "null",
        "{}",
        "{\"version\":1,\"roots\":{},\"paused\":false}",
        "{\"version\":1,\"roots\":[],\"paused\":0}",
    ] {
        assert!(validate_settings(&json(text.as_bytes()).unwrap()).is_err());
    }
}

#[test]
fn cleanup_strict_boundary_uses_each_eligible_row_clock() {
    let path = std::env::temp_dir().join(format!(
        "c2l-store-unit-{}-{}",
        std::process::id(),
        TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    let store = Store::new(&path);
    let directory = path.join("onboarding");
    std::fs::create_dir(&directory).unwrap();
    let time = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    for n in 0..64 {
        let file = std::fs::File::create(directory.join(format!("onboarding-flow-{n:032x}.json")))
            .unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(time))
            .unwrap();
    }
    let key = "onboarding-flow-00000000000000000000000000000000";
    let calls = std::cell::Cell::new(0);
    let edge = 1_700_000_000_000.0 + 48.0 * 3600000.0;
    store
        .save_private_at(key, &json(b"{}").unwrap(), || {
            calls.set(calls.get() + 1);
            edge
        })
        .unwrap();
    assert_eq!(calls.get(), 63);
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 64);
    store
        .save_private_at(key, &json(b"{}").unwrap(), || edge + 1.0)
        .unwrap();
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    std::fs::remove_dir_all(path).unwrap();
}
