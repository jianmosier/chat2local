use chat2local_js_value_compat::{Document, Limits, Value, ValueId};
pub const LIMITS: Limits = Limits {
    input_units: 25 * 1024 * 1024,
    nodes: 13 * 1024 * 1024,
    depth: 131_072,
    output_bytes: 160 * 1024 * 1024,
};
pub fn property(doc: &Document, id: ValueId, name: &str) -> Result<Option<ValueId>, ()> {
    match doc.value(id).map_err(|_| ())? {
        Value::Null | Value::Undefined => Err(()),
        Value::Object(o) => Ok(o.get(&name.encode_utf16().collect::<Vec<_>>())),
        Value::SparseArray { properties, .. } => {
            Ok(properties.get(&name.encode_utf16().collect::<Vec<_>>()))
        }
        _ => Ok(None),
    }
}
pub fn truthy(doc: &Document, id: ValueId) -> Result<bool, ()> {
    Ok(match doc.value(id).map_err(|_| ())? {
        Value::Undefined | Value::Null => false,
        Value::Bool(v) => *v,
        Value::Number(v) => *v != 0.0 && !v.is_nan(),
        Value::String(v) => !v.is_empty(),
        _ => true,
    })
}
pub fn string(doc: &Document, id: Option<ValueId>) -> Result<Vec<u16>, ()> {
    let Some(id) = id else {
        return Ok("undefined".encode_utf16().collect());
    };
    // Explicit work stack: nested JSON arrays must not acquire an arbitrary
    // recursion cutoff or consume the native/WASM call stack during join.
    enum Frame {
        Enter(ValueId),
        ArrayItem(ValueId, usize),
        Exit(String),
    }
    let mut pending = vec![Frame::Enter(id)];
    let mut active = std::collections::HashSet::new();
    let mut out = Vec::new();
    while let Some(frame) = pending.pop() {
        let id = match frame {
            Frame::Exit(key) => {
                active.remove(&key);
                continue;
            }
            Frame::ArrayItem(id, index) => {
                let (length, item) = match doc.value(id).map_err(|_| ())? {
                    Value::Array(items) => (items.len(), items.get(index).copied()),
                    Value::SparseArray { length, properties } => {
                        let key = index.to_string().encode_utf16().collect::<Vec<_>>();
                        (*length as usize, properties.get(&key))
                    }
                    _ => return Err(()),
                };
                if index < length {
                    if index != 0 {
                        out.push(44);
                    }
                    pending.push(Frame::ArrayItem(id, index + 1));
                    if let Some(item) = item
                        && !matches!(
                            doc.value(item).map_err(|_| ())?,
                            Value::Undefined | Value::Null
                        )
                    {
                        pending.push(Frame::Enter(item));
                    }
                }
                if out.len() > LIMITS.input_units || pending.len() > LIMITS.nodes {
                    return Err(());
                }
                continue;
            }
            Frame::Enter(id) => id,
        };
        match doc.value(id).map_err(|_| ())? {
            Value::Undefined => out.extend("undefined".encode_utf16()),
            Value::Null => out.extend("null".encode_utf16()),
            Value::Bool(b) => out.extend(if *b { "true" } else { "false" }.encode_utf16()),
            Value::String(s) => out.extend(s),
            Value::Number(n) if !n.is_finite() => out.extend(
                if n.is_nan() {
                    "NaN"
                } else if *n < 0.0 {
                    "-Infinity"
                } else {
                    "Infinity"
                }
                .encode_utf16(),
            ),
            Value::Number(n) => {
                let mut copy = Document::new().map_err(|_| ())?;
                let value = copy.add(Value::Number(*n), LIMITS.nodes).map_err(|_| ())?;
                copy.set_root(value).map_err(|_| ())?;
                out.extend(
                    copy.stringify(LIMITS)
                        .map_err(|_| ())?
                        .ok_or(())?
                        .encode_utf16(),
                );
            }
            Value::Object(o) => {
                // JSON cannot contain callable valueOf/toString. An own
                // non-callable toString shadows the inherited method.
                if o.get(&"toString".encode_utf16().collect::<Vec<_>>())
                    .is_some()
                {
                    return Err(());
                }
                out.extend("[object Object]".encode_utf16());
            }
            Value::Array(_) | Value::SparseArray { .. } => {
                if let Value::SparseArray { properties, .. } = doc.value(id).map_err(|_| ())? {
                    if properties
                        .get(&"toString".encode_utf16().collect::<Vec<_>>())
                        .is_some()
                    {
                        return Err(());
                    }
                    if properties
                        .get(&"join".encode_utf16().collect::<Vec<_>>())
                        .is_some()
                    {
                        out.extend("[object Array]".encode_utf16());
                        if out.len() > LIMITS.input_units {
                            return Err(());
                        }
                        continue;
                    }
                }
                let key = format!("{id:?}");
                if active.insert(key.clone()) {
                    if let Value::SparseArray { length, .. } = doc.value(id).map_err(|_| ())?
                        && *length as usize > LIMITS.input_units
                    {
                        return Err(());
                    }
                    pending.push(Frame::Exit(key));
                    pending.push(Frame::ArrayItem(id, 0));
                }
            }
        }
        if out.len() > LIMITS.input_units || pending.len() > LIMITS.nodes {
            return Err(());
        }
    }
    Ok(out)
}
pub fn number(doc: &Document, id: Option<ValueId>) -> Result<f64, ()> {
    let Some(id) = id else {
        return Ok(f64::NAN);
    };
    match doc.value(id).map_err(|_| ())? {
        Value::Undefined => Ok(f64::NAN),
        Value::Null => Ok(0.0),
        Value::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => Ok(*n),
        _ => Ok(parse_number(&string(doc, Some(id))?)),
    }
}

fn whitespace(c: char) -> bool {
    matches!(c, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}
fn parse_number(units: &[u16]) -> f64 {
    let Ok(s) = String::from_utf16(units) else {
        return f64::NAN;
    };
    let s = s.trim_matches(whitespace);
    if s.is_empty() {
        return 0.0;
    }
    if matches!(s, "Infinity" | "+Infinity") {
        return f64::INFINITY;
    }
    if s == "-Infinity" {
        return f64::NEG_INFINITY;
    }
    if s.len() > 2 && s.starts_with('0') {
        let radix = match s.as_bytes()[1] {
            b'x' | b'X' => 16,
            b'o' | b'O' => 8,
            b'b' | b'B' => 2,
            _ => 0,
        };
        if radix != 0 {
            let mut n = 0.0;
            for c in s[2..].chars() {
                let Some(d) = c.to_digit(radix) else {
                    return f64::NAN;
                };
                n = n * f64::from(radix) + f64::from(d);
            }
            return n;
        }
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.' | b'e' | b'E'))
    {
        return f64::NAN;
    }
    s.parse().unwrap_or(f64::NAN)
}
pub fn base64(units: &[u16]) -> Result<Vec<u8>, ()> {
    let mut input: Vec<u16> = units
        .iter()
        .copied()
        .filter(|c| !matches!(c, 9 | 10 | 12 | 13 | 32))
        .collect();
    if input.len().is_multiple_of(4) {
        if input.last() == Some(&61) {
            input.pop();
        }
        if input.last() == Some(&61) {
            input.pop();
        }
    }
    if input.len() % 4 == 1 {
        return Err(());
    }
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for unit in input {
        let digit = match unit {
            65..=90 => unit - 65,
            97..=122 => unit - 71,
            48..=57 => unit + 4,
            43 => 62,
            47 => 63,
            _ => return Err(()),
        };
        bits = (bits << 6) | u32::from(digit);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Ok(out)
}
pub fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(ALPHABET[usize::from(a >> 2)]));
        out.push(char::from(ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(c & 63)])
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod string_tests {
    use super::*;
    use chat2local_js_value_compat::Object;

    #[test]
    fn arrays_only_suppress_active_ancestors() {
        let mut doc = Document::new().unwrap();
        let text = doc.add(Value::String(vec![120]), LIMITS.nodes).unwrap();
        let dense = doc.add(Value::Array(vec![]), LIMITS.nodes).unwrap();
        let sparse = doc
            .add(
                Value::SparseArray {
                    length: 2,
                    properties: Object::default(),
                },
                LIMITS.nodes,
            )
            .unwrap();
        doc.push(dense, text).unwrap();
        doc.push(dense, sparse).unwrap();
        doc.set_property(sparse, vec![48], dense).unwrap();
        doc.set_property(sparse, vec![49], text).unwrap();
        let root = doc
            .add(Value::Array(vec![dense, dense]), LIMITS.nodes)
            .unwrap();
        assert_eq!(
            String::from_utf16(&string(&doc, Some(root)).unwrap()).unwrap(),
            "x,,x,x,,x"
        );
        let self_ref = doc.add(Value::Array(vec![]), LIMITS.nodes).unwrap();
        doc.push(self_ref, self_ref).unwrap();
        assert_eq!(string(&doc, Some(self_ref)).unwrap(), Vec::<u16>::new());
    }
}
