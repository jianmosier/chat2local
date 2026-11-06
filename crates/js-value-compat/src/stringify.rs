use super::{
    Document, Error, ErrorKind, JsString, Limits, Object, Value, ValueId, array_index, error,
};
use std::collections::HashSet;

struct Output {
    text: String,
    limit: usize,
}
impl Output {
    fn write(&mut self, text: &str) -> Result<(), Error> {
        if text.len() > self.limit.saturating_sub(self.text.len()) {
            return Err(error(ErrorKind::Limit));
        }
        self.text.push_str(text);
        Ok(())
    }
    fn character(&mut self, value: char) -> Result<(), Error> {
        self.write(value.encode_utf8(&mut [0; 4]))
    }
    fn escaped(&mut self, unit: u16) -> Result<(), Error> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let bytes = [
            b'\\',
            b'u',
            HEX[(unit >> 12) as usize],
            HEX[((unit >> 8) & 15) as usize],
            HEX[((unit >> 4) & 15) as usize],
            HEX[(unit & 15) as usize],
        ];
        self.write(std::str::from_utf8(&bytes).expect("ASCII escape"))
    }
    fn string(&mut self, units: &[u16]) -> Result<(), Error> {
        self.write("\"")?;
        let mut position = 0;
        while let Some(&unit) = units.get(position) {
            position += 1;
            match unit {
                8 => self.write("\\b")?,
                9 => self.write("\\t")?,
                10 => self.write("\\n")?,
                12 => self.write("\\f")?,
                13 => self.write("\\r")?,
                34 => self.write("\\\"")?,
                92 => self.write("\\\\")?,
                0..=31 => self.escaped(unit)?,
                0xd800..=0xdbff => {
                    if let Some(&low @ 0xdc00..=0xdfff) = units.get(position) {
                        position += 1;
                        self.character(
                            char::from_u32(
                                0x10000
                                    + (u32::from(unit - 0xd800) << 10)
                                    + u32::from(low - 0xdc00),
                            )
                            .unwrap(),
                        )?;
                    } else {
                        self.escaped(unit)?;
                    }
                }
                0xdc00..=0xdfff => self.escaped(unit)?,
                _ => self.character(char::from_u32(u32::from(unit)).unwrap())?,
            }
        }
        self.write("\"")
    }
}
enum Frame<'a> {
    Enter(ValueId, usize),
    Array {
        id: ValueId,
        items: &'a [ValueId],
        index: usize,
        depth: usize,
    },
    SparseArray {
        id: ValueId,
        properties: &'a Object,
        length: u32,
        index: u32,
        depth: usize,
    },
    Object {
        id: ValueId,
        entries: &'a [(JsString, ValueId)],
        order: Vec<usize>,
        index: usize,
        depth: usize,
    },
}
pub(super) fn stringify(doc: &Document, limits: Limits) -> Result<Option<String>, Error> {
    if doc.len() > limits.nodes {
        return Err(error(ErrorKind::Limit));
    }
    if matches!(doc.value(doc.root)?, Value::Undefined) {
        return Ok(None);
    }
    let mut out = Output {
        text: String::new(),
        limit: limits.output_bytes,
    };
    let mut stack = vec![Frame::Enter(doc.root, 0)];
    let mut active = HashSet::new();
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(id, depth) => match doc.value(id)? {
                Value::Undefined | Value::Null => out.write("null")?,
                Value::Bool(value) => out.write(if *value { "true" } else { "false" })?,
                Value::Number(value) => {
                    if !value.is_finite() {
                        out.write("null")?;
                    } else if *value == 0.0 {
                        out.write("0")?;
                    } else {
                        out.write(ryu_js::Buffer::new().format_finite(*value))?;
                    }
                }
                Value::String(value) => out.string(value)?,
                Value::Array(items) => {
                    if depth >= limits.depth {
                        return Err(error(ErrorKind::Limit));
                    }
                    if !active.insert(id.index) {
                        return Err(error(ErrorKind::Cycle));
                    }
                    out.write("[")?;
                    stack.push(Frame::Array {
                        id,
                        items,
                        index: 0,
                        depth: depth + 1,
                    });
                }
                Value::SparseArray { length, properties } => {
                    if depth >= limits.depth {
                        return Err(error(ErrorKind::Limit));
                    }
                    if !active.insert(id.index) {
                        return Err(error(ErrorKind::Cycle));
                    }
                    // Each element requires at least one byte, plus separators.
                    if (*length as usize).saturating_mul(2).saturating_sub(1)
                        > limits.output_bytes.saturating_sub(out.text.len())
                    {
                        return Err(error(ErrorKind::Limit));
                    }
                    out.write("[")?;
                    stack.push(Frame::SparseArray {
                        id,
                        properties,
                        length: *length,
                        index: 0,
                        depth: depth + 1,
                    });
                }
                Value::Object(object) => {
                    if depth >= limits.depth {
                        return Err(error(ErrorKind::Limit));
                    }
                    if !active.insert(id.index) {
                        return Err(error(ErrorKind::Cycle));
                    }
                    let mut integer = Vec::new();
                    let mut rest = Vec::new();
                    for (index, (key, value)) in object.entries().iter().enumerate() {
                        if matches!(doc.value(*value)?, Value::Undefined) {
                            continue;
                        }
                        if let Some(number) = array_index(key) {
                            integer.push((number, index));
                        } else {
                            rest.push(index);
                        }
                    }
                    integer.sort_unstable_by_key(|(number, _)| *number);
                    let order = integer
                        .into_iter()
                        .map(|(_, index)| index)
                        .chain(rest)
                        .collect();
                    out.write("{")?;
                    stack.push(Frame::Object {
                        id,
                        entries: object.entries(),
                        order,
                        index: 0,
                        depth: depth + 1,
                    });
                }
            },
            Frame::Array {
                id,
                items,
                index,
                depth,
            } => {
                if let Some(item) = items.get(index) {
                    if index != 0 {
                        out.write(",")?;
                    }
                    stack.push(Frame::Array {
                        id,
                        items,
                        index: index + 1,
                        depth,
                    });
                    stack.push(Frame::Enter(*item, depth));
                } else {
                    out.write("]")?;
                    active.remove(&id.index);
                }
            }
            Frame::SparseArray {
                id,
                properties,
                length,
                index,
                depth,
            } => {
                if index < length {
                    if index != 0 {
                        out.write(",")?;
                    }
                    stack.push(Frame::SparseArray {
                        id,
                        properties,
                        length,
                        index: index + 1,
                        depth,
                    });
                    let key: Vec<u16> = index.to_string().encode_utf16().collect();
                    if let Some(item) = properties.get(&key) {
                        stack.push(Frame::Enter(item, depth));
                    } else {
                        out.write("null")?;
                    }
                } else {
                    out.write("]")?;
                    active.remove(&id.index);
                }
            }
            Frame::Object {
                id,
                entries,
                order,
                index,
                depth,
            } => {
                if let Some(&entry) = order.get(index) {
                    if index != 0 {
                        out.write(",")?;
                    }
                    let (key, value) = &entries[entry];
                    out.string(key)?;
                    out.write(":")?;
                    stack.push(Frame::Object {
                        id,
                        entries,
                        order,
                        index: index + 1,
                        depth,
                    });
                    stack.push(Frame::Enter(*value, depth));
                } else {
                    out.write("}")?;
                    active.remove(&id.index);
                }
            }
        }
    }
    Ok(Some(out.text))
}
