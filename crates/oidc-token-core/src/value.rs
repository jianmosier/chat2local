use chat2local_js_value_compat::{Document, Limits, Value, ValueId};
use serde::Deserialize;
use serde_json::{Value as Json, json};

pub const LIMITS: Limits = Limits {
    input_units: 4_194_304,
    nodes: 2_097_152,
    depth: 4_194_304,
    output_bytes: 16_777_216,
};
pub type Result<T> = std::result::Result<T, Json>;
pub fn error(message: &str) -> Json {
    json!({"kind":"error","message":message,"status":401})
}
pub fn generic() -> Json {
    error("Identity token signature or claims did not verify.")
}
pub fn unavailable() -> Json {
    json!({"kind":"unavailable"})
}
pub fn native(property: &str) -> Json {
    json!({"kind":"native","property":property})
}
pub fn parse(units: &[u16]) -> Result<Document> {
    Document::parse_utf16(units, LIMITS).map_err(|e| {
        if e.kind == chat2local_js_value_compat::ErrorKind::Limit {
            unavailable()
        } else {
            generic()
        }
    })
}
pub fn val(d: &Document, id: ValueId) -> &Value {
    d.value(id).expect("owned JSON value")
}
pub fn prop(d: &Document, id: ValueId, key: &str) -> Option<ValueId> {
    d.get_property(id, &key.encode_utf16().collect::<Vec<_>>())
        .ok()
        .flatten()
}
pub fn string(d: &Document, id: ValueId) -> Option<&[u16]> {
    if let Value::String(s) = val(d, id) {
        Some(s)
    } else {
        None
    }
}
pub fn is(d: &Document, id: ValueId, s: &str) -> bool {
    string(d, id).is_some_and(|v| v.iter().copied().eq(s.encode_utf16()))
}
pub fn truth(d: &Document, id: Option<ValueId>) -> bool {
    match id.map(|id| val(d, id)) {
        None | Some(Value::Undefined | Value::Null | Value::Bool(false)) => false,
        Some(Value::Number(n)) => *n != 0.0 && !n.is_nan(),
        Some(Value::String(s)) => !s.is_empty(),
        _ => true,
    }
}
pub fn field_is(d: &Document, id: ValueId, k: &str, s: &str) -> bool {
    prop(d, id, k).is_some_and(|v| is(d, v, s))
}
pub fn num(d: &Document, id: ValueId) -> Option<f64> {
    if let Value::Number(n) = val(d, id) {
        Some(*n)
    } else {
        None
    }
}
pub fn array(d: &Document, id: ValueId) -> Option<&[ValueId]> {
    if let Value::Array(a) = val(d, id) {
        Some(a)
    } else {
        None
    }
}
pub fn object(d: &Document, id: ValueId) -> bool {
    matches!(val(d, id), Value::Object(_))
}
pub fn same(d: &Document, id: ValueId, s: &Scalar) -> bool {
    match s {
        Scalar::String { units } => string(d, id) == Some(units.as_slice()),
        Scalar::Bool { value } => matches!(val(d,id),Value::Bool(v) if v==value),
        Scalar::Null => matches!(val(d, id), Value::Null),
        Scalar::Number { bits } => num(d, id).is_some_and(|n| n == number(bits)),
        _ => false,
    }
}
pub fn number(bits: &str) -> f64 {
    u64::from_str_radix(bits, 16)
        .map(f64::from_bits)
        .unwrap_or(f64::NAN)
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scalar {
    Undefined,
    Null,
    Bool { value: bool },
    Number { bits: String },
    String { units: Vec<u16> },
    LongString { length16: u64 },
    Object,
    Array,
}
impl Scalar {
    pub fn string(&self) -> Option<&[u16]> {
        if let Self::String { units } = self {
            Some(units)
        } else {
            None
        }
    }
    pub fn string_type(&self) -> bool {
        matches!(self, Self::String { .. } | Self::LongString { .. })
    }
    pub fn length(&self) -> u64 {
        match self {
            Self::String { units } => units.len() as u64,
            Self::LongString { length16 } => *length16,
            _ => 0,
        }
    }
    pub fn truth(&self) -> bool {
        match self {
            Self::Undefined | Self::Null | Self::Bool { value: false } => false,
            Self::Number { bits } => {
                let n = number(bits);
                n != 0.0 && !n.is_nan()
            }
            Self::String { units } => !units.is_empty(),
            _ => true,
        }
    }
    pub fn numeric(&self) -> f64 {
        match self {
            Self::Number { bits } => number(bits),
            Self::Null | Self::Bool { value: false } => 0.0,
            Self::Bool { value: true } => 1.0,
            Self::String { units } => {
                let s = String::from_utf16_lossy(units);
                js_number(&s)
            }
            _ => f64::NAN,
        }
    }
}

fn js_number(s: &str) -> f64 {
    let s=s.trim_matches(|c| matches!(c,'\u{0009}'..='\u{000d}'|'\u{0020}'|'\u{00a0}'|'\u{1680}'|'\u{2000}'..='\u{200a}'|'\u{2028}'|'\u{2029}'|'\u{202f}'|'\u{205f}'|'\u{3000}'|'\u{feff}'));
    if s.is_empty() {
        return 0.0;
    }
    if matches!(s, "Infinity" | "+Infinity") {
        return f64::INFINITY;
    }
    if s == "-Infinity" {
        return f64::NEG_INFINITY;
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0b", 2),
        ("0B", 2),
        ("0o", 8),
        ("0O", 8),
    ] {
        if let Some(digits) = s.strip_prefix(prefix) {
            if digits.is_empty() {
                return f64::NAN;
            }
            let mut n = 0.0;
            for c in digits.chars() {
                let Some(d) = c.to_digit(radix) else {
                    return f64::NAN;
                };
                n = n * f64::from(radix) + f64::from(d);
            }
            return n;
        }
    }
    if s.chars()
        .any(|c| !matches!(c, '0'..='9' | '+' | '-' | '.' | 'e' | 'E'))
    {
        return f64::NAN;
    }
    s.parse().unwrap_or(f64::NAN)
}

#[derive(Deserialize)]
#[serde(tag = "tag", rename_all = "snake_case", deny_unknown_fields)]
pub enum NumericNode {
    Scalar { value: Scalar },
    Object { blocked: bool },
    Array { items: Vec<usize>, blocked: bool },
}
/// Independent flat snapshot for ordinary JSON clock arguments. No effects,
/// provider values, host coercion verdict or recursive serialization is used.
pub fn numeric_graph(nodes: &[NumericNode]) -> Result<f64> {
    enum Work {
        Node(usize),
        Comma,
        Leave(usize),
    }
    let mut work = vec![Work::Node(0)];
    let mut active = std::collections::HashSet::new();
    let mut out = String::new();
    while let Some(item) = work.pop() {
        match item {
            Work::Comma => out.push(','),
            Work::Leave(id) => {
                active.remove(&id);
            }
            Work::Node(id) => match nodes.get(id).ok_or_else(unavailable)? {
                NumericNode::Scalar { value } => match value {
                    Scalar::Null | Scalar::Undefined => (),
                    Scalar::String { units } => out.push_str(&String::from_utf16_lossy(units)),
                    Scalar::Number { bits } => {
                        let n = number(bits);
                        out.push_str(&if n.is_nan() {
                            "NaN".into()
                        } else if n == f64::INFINITY {
                            "Infinity".into()
                        } else if n == f64::NEG_INFINITY {
                            "-Infinity".into()
                        } else {
                            n.to_string()
                        });
                    }
                    Scalar::Bool { value } => out.push_str(if *value { "true" } else { "false" }),
                    _ => return Err(unavailable()),
                },
                NumericNode::Object { blocked } => {
                    if *blocked {
                        return Err(json!({"kind":"native_coercion"}));
                    }
                    out.push_str("[object Object]");
                }
                NumericNode::Array { items, blocked } => {
                    if *blocked {
                        return Err(json!({"kind":"native_coercion"}));
                    }
                    if active.insert(id) {
                        work.push(Work::Leave(id));
                        for (i, node) in items.iter().enumerate().rev() {
                            work.push(Work::Node(*node));
                            if i > 0 {
                                work.push(Work::Comma);
                            }
                        }
                    }
                }
            },
        }
        if out.len() > LIMITS.output_bytes {
            return Err(unavailable());
        }
    }
    Ok(js_number(&out))
}

/// WebIDL DOMString conversion for JSON data. This is unrelated to token or
/// issuer decisions. JSON objects with own noncallable conversion methods fail.
pub fn dom_string(d: &Document, id: ValueId) -> Option<Vec<u16>> {
    enum Work {
        Value(ValueId),
        Comma,
    }
    let mut stack = vec![Work::Value(id)];
    let mut out = Vec::new();
    while let Some(item) = stack.pop() {
        match item {
            Work::Comma => out.push(44),
            Work::Value(id) => match val(d, id) {
                Value::String(s) => out.extend_from_slice(s),
                Value::Null => out.extend("null".encode_utf16()),
                Value::Bool(b) => out.extend(if *b { "true" } else { "false" }.encode_utf16()),
                Value::Number(n) => {
                    let doc = Document::parse_str(
                        &if n.is_finite() {
                            n.to_string()
                        } else {
                            "null".into()
                        },
                        LIMITS,
                    )
                    .ok()?;
                    out.extend(doc.stringify(LIMITS).ok()??.encode_utf16());
                }
                Value::Array(a) => {
                    for (i, v) in a.iter().enumerate().rev() {
                        if !matches!(val(d, *v), Value::Null | Value::Undefined) {
                            stack.push(Work::Value(*v));
                        }
                        if i > 0 {
                            stack.push(Work::Comma);
                        }
                    }
                }
                Value::Object(_) => {
                    if prop(d, id, "toString").is_some() {
                        return None;
                    }
                    out.extend("[object Object]".encode_utf16());
                }
                _ => return None,
            },
        }
        if out.len() > LIMITS.input_units {
            return None;
        }
    }
    Some(out)
}

pub fn base64(input: &[u16], mode: u8) -> Option<Vec<u8>> {
    let data: Vec<u16> = if mode == 0 {
        input.to_vec()
    } else {
        input
            .iter()
            .copied()
            .filter(|c| !matches!(c, 9 | 10 | 12 | 13 | 32))
            .collect()
    };
    let first = data.iter().position(|c| *c == 61).unwrap_or(data.len());
    let pad = data.len() - first;
    if pad > 0
        && (mode == 0
            || pad > 2
            || !data.len().is_multiple_of(4)
            || data[first..].iter().any(|c| *c != 61)
            || first % 4 != (4 - pad))
    {
        return None;
    }
    if first % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(first * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in &data[..first] {
        let n = match c {
            65..=90 => c - 65,
            97..=122 => c - 97 + 26,
            48..=57 => c - 48 + 52,
            45 => 62,
            95 => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(n);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}
pub fn b64(bytes: &[u8]) -> Vec<u16> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(u16::from(table[((acc >> bits) & 63) as usize]));
            acc &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        out.push(u16::from(table[((acc << (6 - bits)) & 63) as usize]));
    }
    out
}
