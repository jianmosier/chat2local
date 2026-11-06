//! Read-only startup check shared with the JS write-fence contract. Never repairs evidence.
use crate::{Document, Error, Result, Value, ValueId, fs};
use std::{io::Read, path::Path};

fn blocked() -> Error {
    Error::new(
        "EFENCE",
        "An unresolved write requires local inspection. Do not retry or use an older release.",
    )
}
fn exists(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(blocked()),
    }
}
fn uuid(s: &str) -> bool {
    let parts = s.split('-').collect::<Vec<_>>();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(s, n)| lower_hex(s, n))
}
fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn get(doc: &Document, object: ValueId, key: &str) -> Result<ValueId> {
    doc.get_property(object, &key.encode_utf16().collect::<Vec<_>>())?
        .ok_or_else(blocked)
}
fn string(doc: &Document, id: ValueId) -> Result<&[u16]> {
    match doc.value(id)? {
        Value::String(s) => Ok(s),
        _ => Err(blocked()),
    }
}
fn text(doc: &Document, object: ValueId, key: &str) -> Result<String> {
    String::from_utf16(string(doc, get(doc, object, key)?)?).map_err(|_| blocked())
}
fn fields(doc: &Document, id: ValueId, expected: &[&str]) -> Result<()> {
    let Value::Object(object) = doc.value(id)? else {
        return Err(blocked());
    };
    if object.entries().len() != expected.len() {
        return Err(blocked());
    }
    for key in expected {
        get(doc, id, key)?;
    }
    Ok(())
}
fn nullable_hash(doc: &Document, object: ValueId, key: &str, n: usize) -> Result<()> {
    let id = get(doc, object, key)?;
    if matches!(doc.value(id)?, Value::Null) || lower_hex(&text(doc, object, key)?, n) {
        Ok(())
    } else {
        Err(blocked())
    }
}
fn valid(doc: &Document, name: &str) -> Result<()> {
    let root = doc.root();
    fields(
        doc,
        root,
        &["v", "operationId", "intent", "sha256", "phase", "binding"],
    )?;
    if !matches!(doc.value(get(doc, root, "v")?)?, Value::Number(n) if *n == 1.0)
        || format!("{}.json", text(doc, root, "operationId")?) != name
        || !lower_hex(&text(doc, root, "intent")?, 64)
        || !lower_hex(&text(doc, root, "sha256")?, 64)
        || !["complete", "aborted"].contains(&text(doc, root, "phase")?.as_str())
    {
        return Err(blocked());
    }
    let binding = get(doc, root, "binding")?;
    fields(
        doc,
        binding,
        &[
            "rootId",
            "rootPath",
            "path",
            "beforeHash",
            "deviceId",
            "resource",
            "connectionId",
            "fileId",
        ],
    )?;
    let id = text(doc, binding, "rootId")?;
    if id.is_empty()
        || id.len() > 80
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err(blocked());
    }
    // JS strings may contain lone surrogates. These strings are validated, never used for I/O.
    let root_path = string(doc, get(doc, binding, "rootPath")?)?;
    #[cfg(windows)]
    let absolute = matches!(root_path.first(), Some(47 | 92))
        || (root_path.len() >= 3
            && ((65..=90).contains(&root_path[0]) || (97..=122).contains(&root_path[0]))
            && root_path[1] == 58
            && matches!(root_path[2], 47 | 92));
    #[cfg(not(windows))]
    let absolute = root_path.first() == Some(&47);
    if !absolute {
        return Err(blocked());
    }
    let relative = String::from_utf16_lossy(string(doc, get(doc, binding, "path")?)?);
    chat2local_policy::relative_parts(&relative, false).map_err(|_| blocked())?;
    nullable_hash(doc, binding, "beforeHash", 64)?;
    nullable_hash(doc, binding, "deviceId", 32)?;
    nullable_hash(doc, binding, "connectionId", 32)?;
    let resource = get(doc, binding, "resource")?;
    if !matches!(doc.value(resource)?, Value::Null) && string(doc, resource)?.len() > 2048 {
        return Err(blocked());
    }
    match doc.value(get(doc, binding, "fileId")?)? {
        Value::Null => {}
        Value::Array(items) if items.len() == 3 => {
            for id in items {
                if !matches!(doc.value(*id)?, Value::Number(n) if n.fract() == 0.0 && *n >= 0.0 && *n <= u32::MAX as f64)
                {
                    return Err(blocked());
                }
            }
        }
        _ => return Err(blocked()),
    }
    Ok(())
}
pub fn assert_write_fence_clear(directory: &Path) -> Result<()> {
    check_fence(directory, false)
}
pub fn check_fence(directory: &Path, own_gate: bool) -> Result<()> {
    if !own_gate && exists(&directory.join("write-gate"))?.is_some() {
        return Err(blocked());
    }
    let directory = directory.join("rust-writes");
    let Some(meta) = exists(&directory)? else {
        return Ok(());
    };
    fs::parent_safe(&directory).map_err(|_| blocked())?;
    if !meta.is_dir() {
        return Err(blocked());
    }
    for entry in std::fs::read_dir(&directory).map_err(|_| blocked())? {
        let entry = entry.map_err(|_| blocked())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(blocked)?;
        if name == "writer.lock" || name.strip_suffix(".before").is_some_and(uuid) {
            continue;
        }
        if !name.strip_suffix(".json").is_some_and(uuid) {
            return Err(blocked());
        }
        let mut data = Vec::new();
        fs::open_private(&entry.path(), 16384)
            .map_err(|_| blocked())?
            .take(16385)
            .read_to_end(&mut data)
            .map_err(|_| blocked())?;
        if data.len() > 16384 {
            return Err(blocked());
        }
        // Reuse JS JSON semantics: duplicate keys, numeric spellings and UTF-16 values.
        valid(&crate::json(&data).map_err(|_| blocked())?, name).map_err(|_| blocked())?;
    }
    Ok(())
}
