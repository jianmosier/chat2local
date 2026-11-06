//! Request-private OIDC decisions. URL/cookie parsing, storage and cryptography
//! remain host responsibilities. No storage or provider effects exist here.
use serde::{Deserialize, Serialize};

pub const FRAME_BYTES: usize = 65_536;
const MAX_SAFE: u64 = 9_007_199_254_740_991;

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
    Begin {
        is_string: bool,
        length16: u64,
        prefix: Vec<u16>,
        target: Option<Target>,
    },
    CallbackPre {
        counts: [u64; 4],
        state: Option<Vec<u16>>,
    },
    CallbackCookie {
        cookie: Option<Vec<u16>>,
    },
    CallbackAfterTake {
        has_error: bool,
        code: Code,
        iss_present: bool,
        issuer_length16: u64,
        expected_length16: u64,
    },
    IssuerChunk {
        offset: u64,
        actual: Vec<u16>,
        expected: Vec<u16>,
    },
    IssuerFinish,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    same_origin: bool,
    has_hash: bool,
    pathname_length16: u64,
    pathname_prefix: Vec<u16>,
    other_keys: bool,
    connections: u64,
    connection_length16: u64,
    connection: Vec<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Code {
    present: bool,
    length16: u64,
    units: Option<Vec<u16>>,
}

#[derive(Serialize, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    Accepted,
    CodeAccepted { code: Vec<u16> },
    Cookie,
    Take,
    Comparing { total: u64, offset: u64 },
    Rejected { status: u16, message: &'static str },
}

#[derive(Default)]
enum Stage {
    #[default]
    New,
    Cookie,
    AfterTake,
    Comparing {
        total: u64,
        offset: u64,
        equal: bool,
        code: Vec<u16>,
    },
    Complete,
}

#[derive(Default)]
pub struct Engine {
    serial: u64,
    stage: Stage,
    failed: bool,
}

fn reject(status: u16, message: &'static str) -> Decision {
    Decision::Rejected { status, message }
}
fn provider_rejection() -> Decision {
    reject(401, "Identity provider did not complete this sign-in.")
}
fn secret(value: &[u16]) -> bool {
    value.len() == 64 && value.iter().all(|c| matches!(c, 48..=57 | 97..=102))
}
fn text(value: &[u16], expected: &str) -> bool {
    value.iter().copied().eq(expected.encode_utf16())
}

impl Engine {
    fn apply(&mut self, command: Command) -> Option<Decision> {
        let stage = std::mem::replace(&mut self.stage, Stage::Complete);
        Some(match (stage, command) {
            (
                Stage::New,
                Command::Begin {
                    is_string,
                    length16,
                    prefix,
                    target,
                },
            ) => {
                if length16 > MAX_SAFE || prefix.len() as u64 != length16.min(11) {
                    return None;
                }
                let starts_slash = prefix.first() == Some(&47);
                let authorize =
                    prefix.starts_with(&"/authorize?".encode_utf16().collect::<Vec<_>>());
                let mut valid = false;
                if let Some(t) = target {
                    if t.pathname_length16 > MAX_SAFE
                        || t.connections > MAX_SAFE
                        || t.connection_length16 > MAX_SAFE
                        || t.pathname_prefix.len() as u64 != t.pathname_length16.min(12)
                        || t.connection.len() as u64 != t.connection_length16.min(33)
                    {
                        return None;
                    }
                    let joining = t.pathname_length16 == 12
                        && text(&t.pathname_prefix, "/account/add")
                        && !t.other_keys
                        && t.connections <= 1
                        && (t.connections == 0
                            || (t.connection_length16 == 32
                                && t.connection.iter().all(|c| matches!(c, 48..=57 | 97..=102))));
                    valid = t.same_origin && !t.has_hash && (authorize || joining);
                }
                if is_string && length16 <= 8192 && starts_slash && valid {
                    Decision::Accepted
                } else {
                    reject(400, "Invalid sign-in continuation.")
                }
            }
            (Stage::New, Command::CallbackPre { counts, state }) => {
                if counts.iter().any(|n| *n > MAX_SAFE)
                    || state.as_ref().is_some_and(|s| s.len() != 64)
                {
                    return None;
                }
                if counts.iter().any(|n| *n > 1) {
                    reject(401, "Duplicate identity callback fields.")
                } else if !state.as_ref().is_some_and(|s| secret(s)) {
                    reject(401, "Identity callback state is missing.")
                } else {
                    self.stage = Stage::Cookie;
                    Decision::Cookie
                }
            }
            (Stage::Cookie, Command::CallbackCookie { cookie }) => {
                if cookie.as_ref().is_some_and(|s| s.len() > 64) {
                    return None;
                }
                if cookie.as_ref().is_some_and(|s| secret(s)) {
                    self.stage = Stage::AfterTake;
                    Decision::Take
                } else {
                    reject(
                        401,
                        "This sign-in belongs to another browser or has expired.",
                    )
                }
            }
            (
                Stage::AfterTake,
                Command::CallbackAfterTake {
                    has_error,
                    code,
                    iss_present,
                    issuer_length16,
                    expected_length16,
                },
            ) => {
                if code.length16 > MAX_SAFE
                    || issuer_length16 > MAX_SAFE
                    || expected_length16 > MAX_SAFE
                    || (!code.present && code.length16 != 0)
                    || (code.length16 <= 4096
                        && code.units.as_ref().map(|v| v.len() as u64) != Some(code.length16))
                    || (code.length16 > 4096 && code.units.is_some())
                {
                    return None;
                }
                if has_error || !code.present || code.length16 == 0 || code.length16 > 4096 {
                    provider_rejection()
                } else if !iss_present {
                    Decision::CodeAccepted { code: code.units? }
                } else if issuer_length16 != expected_length16 {
                    provider_rejection()
                } else {
                    self.stage = Stage::Comparing {
                        total: issuer_length16,
                        offset: 0,
                        equal: true,
                        code: code.units?,
                    };
                    Decision::Comparing {
                        total: issuer_length16,
                        offset: 0,
                    }
                }
            }
            (
                Stage::Comparing {
                    total,
                    offset,
                    equal,
                    code,
                },
                Command::IssuerChunk {
                    offset: supplied,
                    actual,
                    expected,
                },
            ) => {
                let size = (total - offset).min(512);
                if size == 0
                    || supplied != offset
                    || actual.len() as u64 != size
                    || expected.len() as u64 != size
                {
                    return None;
                }
                let next = offset.checked_add(size)?;
                self.stage = Stage::Comparing {
                    total,
                    offset: next,
                    equal: equal && actual == expected,
                    code,
                };
                Decision::Comparing {
                    total,
                    offset: next,
                }
            }
            (
                Stage::Comparing {
                    total,
                    offset,
                    equal,
                    code,
                },
                Command::IssuerFinish,
            ) => {
                if offset != total || code.is_empty() {
                    return None;
                }
                if equal {
                    Decision::CodeAccepted { code }
                } else {
                    provider_rejection()
                }
            }
            _ => return None,
        })
    }
}

/// Any malformed frame, serial or stage error permanently poisons the instance.
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
            || frame.serial > MAX_SAFE
            || frame.serial != engine.serial.checked_add(1)?
        {
            return None;
        }
        engine.serial = frame.serial;
        let result = engine.apply(frame.command)?;
        let output = serde_json::to_vec(
            &serde_json::json!({ "v": 1, "serial": frame.serial, "result": result }),
        )
        .ok()?;
        (output.len() <= FRAME_BYTES).then_some(output)
    })();
    if result.is_none() {
        engine.failed = true;
    }
    result
}

#[cfg(test)]
mod tests;
