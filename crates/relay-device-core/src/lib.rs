use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const FRAME_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum Field {
    Missing,
    Null,
    Invalid,
    Number { value: f64 },
    Boolean { value: bool },
}
impl Field {
    fn number(&self) -> Option<f64> {
        match self {
            Self::Number { value } if value.is_finite() => Some(*value),
            _ => None,
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum Attachment {
    Null,
    Invalid,
    Record {
        version: Field,
        #[serde(rename = "connectedAt")]
        connected_at: Field,
        #[serde(rename = "lastSeenAt")]
        last_seen_at: Field,
        retired: Field,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    present: bool,
    revoked: bool,
    epoch: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capability {
    required: bool,
    supported: bool,
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
enum Command {
    LeaseObserve {
        attachment: Attachment,
        open: bool,
        now: Field,
    },
    LeaseTouch {
        attachment: Attachment,
        open: bool,
        now: Field,
    },
    LeaseRetire,
    Admit {
        id: String,
        socket: String,
        epoch: Option<String>,
        identity: Identity,
        capability: Capability,
        live: bool,
    },
    Settle {
        id: Option<String>,
        socket: String,
    },
    Timeout {
        id: Option<String>,
        socket: String,
    },
    Disconnect {
        socket: Option<String>,
    },
    Count,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    v: u32,
    serial: u64,
    command: Command,
}
#[derive(Default)]
pub struct State {
    pending: BTreeMap<String, String>,
}
fn id(value: &str) -> bool {
    value.len() == 36
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase() || b == b'-')
}
fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16
        && !value.starts_with('0')
        && value.bytes().all(|b| b.is_ascii_digit())
}
fn epoch(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn lease(attachment: Attachment, open: bool, now: Field, touch: bool) -> Value {
    let Some(now) = now.number().filter(|v| *v >= 0.0 && open) else {
        return json!({"live":false,"patch":null});
    };
    match attachment {
        Attachment::Null => {
            json!({"live":true,"patch":{"version":1,"connectedAt":now,"lastSeenAt":now,"retired":false}})
        }
        Attachment::Record {
            version,
            connected_at,
            last_seen_at,
            retired,
        } => {
            let live = version.number() == Some(1.0)
                && matches!(retired, Field::Boolean { value: false })
                && connected_at
                    .number()
                    .zip(last_seen_at.number())
                    .is_some_and(|(a, b)| {
                        a >= 0.0 && b >= 0.0 && a <= b && b <= now + 5000.0 && now - b < 75000.0
                    });
            let patch = if live && touch {
                json!({"lastSeenAt":now.max(last_seen_at.number().unwrap())})
            } else {
                Value::Null
            };
            json!({"live":live,"patch":patch})
        }
        Attachment::Invalid => json!({"live":false,"patch":null}),
    }
}
impl State {
    fn execute(&mut self, command: Command) -> Option<Value> {
        Some(match command {
            Command::LeaseObserve {
                attachment,
                open,
                now,
            } => lease(attachment, open, now, false),
            Command::LeaseTouch {
                attachment,
                open,
                now,
            } => lease(attachment, open, now, true),
            Command::LeaseRetire => json!({"patch":{"version":1,"retired":true}}),
            Command::Admit {
                id: request_id,
                socket,
                epoch: expected,
                identity,
                capability,
                live,
            } => {
                if !id(&request_id)
                    || !token(&socket)
                    || expected.as_ref().is_some_and(|s| !epoch(s))
                    || identity.epoch.as_ref().is_some_and(|s| !epoch(s))
                {
                    return None;
                }
                let reason = if !identity.present
                    || identity.revoked
                    || expected.is_none()
                    || expected != identity.epoch
                {
                    Some("revoked")
                } else if !live {
                    Some("offline")
                } else if capability.required && !capability.supported {
                    Some("capability")
                } else if self.pending.contains_key(&request_id) {
                    Some("duplicate")
                } else if self.pending.len() >= 12 {
                    Some("busy")
                } else {
                    None
                };
                if reason.is_none() {
                    self.pending.insert(request_id, socket);
                }
                json!({"admitted":reason.is_none(),"reason":reason})
            }
            Command::Settle {
                id: request_id,
                socket,
            }
            | Command::Timeout {
                id: request_id,
                socket,
            } => {
                if !token(&socket) || request_id.as_ref().is_some_and(|s| !id(s)) {
                    return None;
                }
                let consumed = request_id
                    .filter(|key| self.pending.get(key) == Some(&socket))
                    .into_iter()
                    .collect::<Vec<_>>();
                for key in &consumed {
                    self.pending.remove(key);
                }
                json!({"consumed":consumed})
            }
            Command::Disconnect { socket } => {
                if socket.as_ref().is_some_and(|s| !token(s)) {
                    return None;
                }
                let consumed = self
                    .pending
                    .iter()
                    .filter(|(_, value)| socket.as_ref().is_none_or(|s| s == *value))
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                for key in &consumed {
                    self.pending.remove(key);
                }
                json!({"consumed":consumed})
            }
            Command::Count => json!({"count":self.pending.len()}),
        })
    }
}
pub fn dispatch(state: &mut State, bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() > FRAME_BYTES {
        return None;
    }
    let request: Request = serde_json::from_slice(bytes).ok()?;
    if request.v != 1 || request.serial == 0 || request.serial > 9_007_199_254_740_991 {
        return None;
    }
    let result = state.execute(request.command)?;
    let response =
        serde_json::to_vec(&json!({"v":1,"serial":request.serial,"result":result})).ok()?;
    (response.len() <= FRAME_BYTES).then_some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(state: &mut State, command: Value) -> Value {
        let bytes = serde_json::to_vec(&json!({"v":1,"serial":1,"command":command})).unwrap();
        serde_json::from_slice::<Value>(&dispatch(state, &bytes).unwrap()).unwrap()["result"]
            .clone()
    }
    fn admit(n: usize, socket: &str) -> Value {
        json!({"op":"admit","id":format!("{n:036}"),"socket":socket,"epoch":"a".repeat(64),"identity":{"present":true,"revoked":false,"epoch":"a".repeat(64)},"capability":{"required":true,"supported":true},"live":true})
    }
    #[test]
    fn bounded_membership_is_owned_and_consumed_once() {
        let mut state = State::default();
        for n in 0..12 {
            assert_eq!(run(&mut state, admit(n, "1"))["admitted"], true);
        }
        assert_eq!(run(&mut state, admit(12, "1"))["reason"], "busy");
        assert_eq!(
            run(
                &mut state,
                json!({"op":"settle","id":format!("{:036}",0),"socket":"2"})
            )["consumed"],
            json!([])
        );
        assert_eq!(
            run(
                &mut state,
                json!({"op":"timeout","id":format!("{:036}",0),"socket":"1"})
            )["consumed"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            run(
                &mut state,
                json!({"op":"settle","id":format!("{:036}",0),"socket":"1"})
            )["consumed"],
            json!([])
        );
        assert_eq!(
            run(&mut state, json!({"op":"disconnect","socket":"1"}))["consumed"]
                .as_array()
                .unwrap()
                .len(),
            11
        );
    }
    #[test]
    fn identity_capability_and_instances_are_independent() {
        let mut a = State::default();
        let mut b = State::default();
        let mut request = admit(1, "1");
        request["identity"]["revoked"] = json!(true);
        assert_eq!(run(&mut a, request)["reason"], "revoked");
        assert_eq!(run(&mut a, admit(1, "1"))["admitted"], true);
        assert_eq!(run(&mut b, admit(1, "1"))["admitted"], true);
        run(&mut a, json!({"op":"disconnect","socket":null}));
        assert_eq!(run(&mut b, json!({"op":"count"}))["count"], 1);
    }
    #[test]
    fn lease_strict_boundary_and_null_are_explicit() {
        let mut state = State::default();
        let mut command = json!({"op":"leaseObserve","open":true,"now":{"kind":"number","value":76000},"attachment":{"kind":"record","version":{"kind":"number","value":1},"connectedAt":{"kind":"number","value":1000},"lastSeenAt":{"kind":"number","value":1000},"retired":{"kind":"boolean","value":false}}});
        assert_eq!(run(&mut state, command.clone())["live"], false);
        command["now"]["value"] = json!(75999);
        assert_eq!(run(&mut state, command.clone())["live"], true);
        command["attachment"] = json!({"kind":"invalid"});
        assert_eq!(run(&mut state, command.clone())["live"], false);
        command["attachment"] = json!({"kind":"null"});
        assert_eq!(run(&mut state, command)["live"], true);
    }
    #[test]
    fn malformed_input_cannot_enter_state() {
        let mut state = State::default();
        assert!(dispatch(&mut state, &vec![b' '; FRAME_BYTES + 1]).is_none());
        let mut command = admit(1, "1");
        command["content"] = json!("not accepted");
        assert!(
            dispatch(
                &mut state,
                &serde_json::to_vec(&json!({"v":1,"serial":1,"command":command})).unwrap()
            )
            .is_none()
        );
        assert_eq!(run(&mut state, json!({"op":"count"}))["count"], 0);
    }
}
