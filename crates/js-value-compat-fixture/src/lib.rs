//! Test transport only. No application uses this executable or ABI.
use chat2local_js_value_compat::{Document, Error, ErrorKind, Limits, Object, Value};
use serde::Deserialize;
use sha2::{Digest, Sha256};
pub const FRAME: usize = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: String,
    #[serde(default)]
    input: Vec<u16>,
    #[serde(default)]
    bits: Vec<String>,
    #[serde(default)]
    mutations: Vec<Mutation>,
    limits: Option<RequestLimits>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestLimits {
    input_units: usize,
    nodes: usize,
    depth: usize,
    output_bytes: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    #[serde(default)]
    path: Vec<Vec<u16>>,
    key: Vec<u16>,
    value: Option<Vec<u16>>,
    #[serde(default)]
    remove: bool,
}
fn bad() -> Error {
    Error {
        kind: ErrorKind::WrongType,
        offset: 0,
    }
}
fn apply(request: Request) -> Result<Option<String>, Error> {
    let limits = request.limits.map_or(
        Limits {
            input_units: 1_000_000,
            nodes: 1_000_000,
            depth: 1_000_000,
            output_bytes: FRAME,
        },
        |v| Limits {
            input_units: v.input_units,
            nodes: v.nodes,
            depth: v.depth,
            output_bytes: v.output_bytes,
        },
    );
    let mut doc = match request.op.as_str() {
        "roundtrip" => Document::parse_utf16(&request.input, limits)?,
        "clone" => Document::parse_utf16(&request.input, limits)?.try_clone()?,
        "numbers" => {
            let mut doc = Document::new()?;
            let mut items = Vec::new();
            for bits in request.bits {
                if bits.len() != 16 {
                    return Err(bad());
                }
                let value = u64::from_str_radix(&bits, 16).map_err(|_| bad())?;
                items.push(doc.add(Value::Number(f64::from_bits(value)), limits.nodes)?);
            }
            let root = doc.add(Value::Array(items), limits.nodes)?;
            doc.set_root(root)?;
            doc
        }
        "undefined" => Document::new()?,
        "shared" => {
            let mut doc = Document::new()?;
            let child = doc.add(Value::Object(Object::default()), limits.nodes)?;
            let one = doc.add(Value::Number(1.0), limits.nodes)?;
            doc.set_property(child, vec![120], one)?;
            let root = doc.add(Value::Array(vec![child, child]), limits.nodes)?;
            doc.set_root(root)?;
            doc
        }
        "cycle-array" => {
            let mut doc = Document::new()?;
            let root = doc.add(Value::Array(Vec::new()), limits.nodes)?;
            doc.push(root, root)?;
            doc.set_root(root)?;
            doc
        }
        "special" => {
            let mut doc = Document::new()?;
            let undefined = doc.root();
            let root = doc.add(Value::Object(Object::default()), limits.nodes)?;
            let negative_zero = doc.add(Value::Number(-0.0), limits.nodes)?;
            let nan = doc.add(Value::Number(f64::NAN), limits.nodes)?;
            let infinity = doc.add(Value::Number(f64::INFINITY), limits.nodes)?;
            let array = doc.add(
                Value::Array(vec![undefined, undefined, nan, infinity, negative_zero]),
                limits.nodes,
            )?;
            for (key, value) in [
                ("omit", undefined),
                ("nil", nan),
                ("values", array),
                ("negativeZero", negative_zero),
            ] {
                doc.set_property(root, key.encode_utf16().collect(), value)?;
            }
            doc.set_root(root)?;
            doc
        }
        "cycle" => {
            let mut doc = Document::new()?;
            let root = doc.add(Value::Object(Object::default()), limits.nodes)?;
            doc.set_property(root, vec![120], root)?;
            doc.set_root(root)?;
            doc
        }
        _ => return Err(bad()),
    };
    for mutation in request.mutations {
        let mut object = doc.root();
        for key in mutation.path {
            object = doc.get_property(object, &key)?.ok_or_else(bad)?;
        }
        if mutation.remove {
            doc.remove_property(object, &mutation.key)?;
        } else {
            let value = match mutation.value {
                Some(input) => doc.import(Document::parse_utf16(&input, limits)?, limits.nodes)?,
                None => doc.add(Value::Undefined, limits.nodes)?,
            };
            doc.set_property(object, mutation.key, value)?;
        }
    }
    doc.stringify(limits)
}
pub fn respond(input: &[u8]) -> Vec<u8> {
    let result = if input.len() <= FRAME {
        serde_json::from_slice::<Request>(input).ok()
    } else {
        None
    };
    let value = match result {
        Some(request) => match apply(request) {
            Ok(value) => {
                serde_json::json!({"ok":true,"defined":value.is_some(),"sha256":value.as_ref().map(|v|hex::encode(Sha256::digest(v.as_bytes()))),"json":value})
            }
            Err(error) => {
                serde_json::json!({"ok":false,"error":format!("{:?}",error.kind),"offset":error.offset})
            }
        },
        None => serde_json::json!({"ok":false,"error":"Protocol"}),
    };
    serde_json::to_vec(&value).expect("fixture response")
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    static mut INPUT: [u8; FRAME] = [0; FRAME];
    static mut OUTPUT: Vec<u8> = Vec::new();
    #[unsafe(no_mangle)]
    pub extern "C" fn input_ptr() -> *mut u8 {
        std::ptr::addr_of_mut!(INPUT).cast()
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn command(length: usize) -> u32 {
        if length > FRAME {
            return 1;
        }
        let input = unsafe { std::slice::from_raw_parts(std::ptr::addr_of!(INPUT).cast(), length) };
        unsafe {
            OUTPUT = respond(input);
        }
        0
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn output_ptr() -> *const u8 {
        unsafe { (&*std::ptr::addr_of!(OUTPUT)).as_ptr() }
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn output_len() -> usize {
        unsafe { (&*std::ptr::addr_of!(OUTPUT)).len() }
    }
}
