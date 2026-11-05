//! Independent public-key-only OIDC verifier. Stream resource refusal is 503,
//! never a forged authentication rejection. No provider effects or host crypto.
mod value;
mod verify;
use serde::Deserialize;
use serde_json::{Value as Json, json};
use value::{number, unavailable};
pub const FRAME_BYTES: usize = 65_536;
pub const MAX_WIRE: usize = 16_777_216;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    v: u8,
    serial: u64,
    command: Command,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Start { length: u64 },
    Chunk { offset: u64, bytes: Vec<u8> },
    Eof,
    Skew { bits: String },
    Claims { bits: String },
    Output { offset: u64 },
}
#[derive(Default)]
enum Stage {
    #[default]
    New,
    Upload {
        length: usize,
        data: Vec<u8>,
    },
    Skew(verify::Prepared),
    Claims(verify::Prepared),
    Output {
        data: Vec<u8>,
        offset: usize,
    },
    Complete,
}
#[derive(Default)]
pub struct Engine {
    serial: u64,
    failed: bool,
    stage: Stage,
}
impl Engine {
    fn apply(&mut self, command: Command) -> Option<Json> {
        let stage = std::mem::replace(&mut self.stage, Stage::Complete);
        Some(match (stage, command) {
            (Stage::New, Command::Start { length }) => {
                if length as u128 > MAX_WIRE as u128 {
                    return Some(unavailable());
                }
                self.stage = Stage::Upload {
                    length: length as usize,
                    data: Vec::new(),
                };
                json!({"kind":"upload","offset":0})
            }
            (Stage::Upload { length, mut data }, Command::Chunk { offset, bytes }) => {
                if offset != data.len() as u64
                    || bytes.is_empty()
                    || bytes.len() > 8192
                    || data.len().checked_add(bytes.len())? > length
                {
                    return None;
                }
                data.extend(bytes);
                let offset = data.len();
                self.stage = Stage::Upload { length, data };
                json!({"kind":"upload","offset":offset})
            }
            (Stage::Upload { length, data }, Command::Eof) => {
                if data.len() != length {
                    return None;
                }
                let packet: verify::Packet = serde_json::from_slice(&data).ok()?;
                match verify::pre(packet) {
                    Ok(prepared) => {
                        self.stage = Stage::Skew(prepared);
                        json!({"kind":"url"})
                    }
                    Err(e) => e,
                }
            }
            (Stage::Skew(mut prepared), Command::Skew { bits }) => {
                if !valid_bits(&bits) {
                    return None;
                }
                match prepared.skew(number(&bits)) {
                    Ok(()) => {
                        self.stage = Stage::Claims(prepared);
                        json!({"kind":"clock"})
                    }
                    Err(e) => e,
                }
            }
            (Stage::Claims(prepared), Command::Claims { bits }) => {
                if !valid_bits(&bits) {
                    return None;
                }
                match prepared.finish(number(&bits)) {
                    Ok(value) => {
                        let data = serde_json::to_vec(&value).ok()?;
                        if data.len() > MAX_WIRE {
                            return Some(unavailable());
                        }
                        let length = data.len();
                        self.stage = Stage::Output { data, offset: 0 };
                        json!({"kind":"output","length":length})
                    }
                    Err(e) => e,
                }
            }
            (Stage::Output { data, offset }, Command::Output { offset: supplied }) => {
                if supplied != offset as u64 || offset >= data.len() {
                    return None;
                }
                let next = offset.checked_add(8192)?.min(data.len());
                let bytes = &data[offset..next];
                let eof = next == data.len();
                let result = json!({"kind":"output_chunk","offset":offset,"bytes":bytes,"eof":eof});
                if !eof {
                    self.stage = Stage::Output { data, offset: next };
                }
                result
            }
            _ => return None,
        })
    }
}
fn valid_bits(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn dispatch(engine: &mut Engine, input: &[u8]) -> Option<Vec<u8>> {
    if engine.failed {
        return None;
    }
    let result = (|| {
        if input.len() > FRAME_BYTES {
            return None;
        }
        let frame: Frame = serde_json::from_slice(input).ok()?;
        if frame.v != 1
            || frame.serial > 9_007_199_254_740_991
            || frame.serial != engine.serial.checked_add(1)?
        {
            return None;
        }
        engine.serial = frame.serial;
        let result = engine.apply(frame.command)?;
        let out = serde_json::to_vec(&json!({"v":1,"serial":frame.serial,"result":result})).ok()?;
        (out.len() <= FRAME_BYTES).then_some(out)
    })();
    if result.is_none() {
        engine.failed = true;
    }
    result
}
#[cfg(test)]
mod tests;
