use crate::{Error, Result};
use chat2local_js_value_compat::{Document, Limits, Value, ValueId};
pub const LIMITS: Limits = Limits {
    input_units: usize::MAX,
    nodes: usize::MAX,
    depth: usize::MAX,
    output_bytes: usize::MAX,
};
pub fn parse(input: &[u8]) -> Result<Document> {
    Ok(Document::parse_str(
        std::str::from_utf8(input).map_err(|_| Error::new(400, "Invalid UTF-8."))?,
        LIMITS,
    )?)
}
pub fn get(doc: &Document, id: ValueId, key: &str) -> Option<ValueId> {
    doc.get_property(id, &key.encode_utf16().collect::<Vec<_>>())
        .ok()
        .flatten()
}
pub fn prop(doc: &Document, key: &str) -> Option<ValueId> {
    get(doc, doc.root(), key)
}
pub fn string(doc: &Document, id: Option<ValueId>) -> Option<String> {
    match doc.value(id?).ok()? {
        Value::String(s) => String::from_utf16(s).ok(),
        _ => None,
    }
}
pub fn execution_string(doc: &Document, id: Option<ValueId>) -> Option<String> {
    match doc.value(id?).ok()? {
        Value::String(s) => Some(String::from_utf16_lossy(s)),
        _ => None,
    }
}
pub fn boolean(doc: &Document, id: Option<ValueId>) -> Option<bool> {
    match doc.value(id?).ok()? {
        Value::Bool(s) => Some(*s),
        _ => None,
    }
}
pub fn number(doc: &Document, id: Option<ValueId>) -> Option<f64> {
    match doc.value(id?).ok()? {
        Value::Number(s) => Some(*s),
        _ => None,
    }
}
pub fn array(doc: &Document, id: Option<ValueId>) -> Option<Vec<ValueId>> {
    match doc.value(id?).ok()? {
        Value::Array(s) => Some(s.clone()),
        _ => None,
    }
}
pub fn truthy(doc: &Document, id: Option<ValueId>) -> bool {
    match id.and_then(|id| doc.value(id).ok()) {
        None | Some(Value::Null | Value::Undefined) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => *n != 0.0 && !n.is_nan(),
        Some(Value::String(s)) => !s.is_empty(),
        _ => true,
    }
}
pub fn put(doc: &mut Document, key: &str, value: Value) -> Result<()> {
    let id = doc.add(value, usize::MAX)?;
    doc.set_property(doc.root(), key.encode_utf16().collect(), id)?;
    Ok(())
}
pub fn remove(doc: &mut Document, key: &str) -> Result<()> {
    doc.remove_property(doc.root(), &key.encode_utf16().collect::<Vec<_>>())?;
    Ok(())
}
pub fn fields(doc: &Document, keys: &[&str]) -> Result<()> {
    let Value::Object(o) = doc.value(doc.root())? else {
        return Err(Error::new(400, "Invalid request fields."));
    };
    if o.entries().iter().any(|(key, _)| {
        !keys
            .iter()
            .any(|s| s.encode_utf16().eq(key.iter().copied()))
    }) {
        return Err(Error::new(400, "Invalid request fields."));
    }
    Ok(())
}
pub fn text(value: &str) -> Value {
    Value::String(value.encode_utf16().collect())
}
pub fn serialized(doc: &Document) -> Result<String> {
    doc.stringify(LIMITS)?
        .ok_or_else(|| Error::new(400, "Undefined JSON."))
}
pub fn subtree(doc: &Document, id: ValueId) -> Result<String> {
    let mut out = Document::new()?;
    let mut pending = vec![(id, None)];
    let mut destination = None;
    while let Some((source, parent)) = pending.pop() {
        let value = doc.value(source)?;
        let added = out.add(
            match value {
                Value::Array(_) => Value::Array(vec![]),
                Value::Object(_) => Value::Object(Default::default()),
                other => other.clone(),
            },
            usize::MAX,
        )?;
        if let Some((parent, key)) = parent {
            match key {
                Some(key) => out.set_property(parent, key, added)?,
                None => out.push(parent, added)?,
            }
        } else {
            destination = Some(added);
        }
        match value {
            Value::Array(items) => {
                for item in items.iter().rev() {
                    pending.push((*item, Some((added, None))));
                }
            }
            Value::Object(object) => {
                for (key, item) in object.entries().iter().rev() {
                    pending.push((*item, Some((added, Some(key.clone())))));
                }
            }
            _ => {}
        }
    }
    out.set_root(destination.unwrap())?;
    serialized(&out)
}
