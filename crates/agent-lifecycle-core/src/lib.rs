use serde_json::{Value, json};
use std::collections::VecDeque;
pub const FRAME_BYTES: usize = 65536;
const SAFE: u64 = 9007199254740991;
type Result<T> = std::result::Result<T, &'static str>;

pub struct State {
    phase: &'static str,
    queue: VecDeque<String>,
    ticket: u64,
    revision: u64,
    generation: u64,
    attempt: u64,
    retries: u32,
    bridge: &'static str,
    step: &'static str,
    deadline: u64,
    pong: u64,
    seen: VecDeque<String>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            phase: "starting",
            queue: VecDeque::new(),
            ticket: 0,
            revision: 0,
            generation: 0,
            attempt: 0,
            retries: 0,
            bridge: "not-configured",
            step: "stopped",
            deadline: 0,
            pong: 0,
            seen: VecDeque::new(),
        }
    }
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().filter(|s| s.len() <= 80).ok_or("EINPUT")
}
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .filter(|n| *n <= SAFE - 100000)
        .ok_or("EINPUT")
}
fn next(n: &mut u64) -> Result<()> {
    *n = n
        .checked_add(1)
        .filter(|n| *n <= SAFE)
        .ok_or("ELIFECYCLE")?;
    Ok(())
}
fn keys(v: &Value, names: &[&str]) -> Result<()> {
    if v.as_object()
        .is_some_and(|o| o.len() == names.len() && names.iter().all(|k| o.contains_key(*k)))
    {
        Ok(())
    } else {
        Err("EINPUT")
    }
}
impl State {
    fn token(&self) -> Value {
        json!({"generation":self.generation.to_string(),"attempt":self.attempt.to_string()})
    }
    fn effect(&self, kind: &str) -> Value {
        let mut v = self.token();
        v["type"] = json!(kind);
        v
    }
    fn timer(&self, kind: &str) -> Value {
        let mut v = self.effect("armTimer");
        v["timer"] = json!(kind);
        v["at"] = json!(self.deadline);
        v
    }
    fn current(&self, c: &Value) -> bool {
        let generation = self.generation.to_string();
        let attempt = self.attempt.to_string();
        c["generation"].as_str() == Some(generation.as_str())
            && c["attempt"].as_str() == Some(attempt.as_str())
    }
    fn live(&self) -> bool {
        self.phase == "running" && self.step != "stopped" && self.step != "retry"
    }
    fn stop(&mut self, e: &mut Vec<Value>) -> Result<()> {
        next(&mut self.generation)?;
        self.step = "stopped";
        self.bridge = "disconnected";
        self.deadline = 0;
        e.push(json!({"type":"clearBridge"}));
        Ok(())
    }
    fn connect(&mut self, now: u64, e: &mut Vec<Value>) -> Result<()> {
        next(&mut self.attempt)?;
        self.step = "preparing";
        self.bridge = "connecting";
        self.deadline = now + 15000;
        e.push(self.timer("connect"));
        e.push(self.effect("prepareNetwork"));
        Ok(())
    }
    fn retry(&mut self, now: u64, jitter: u64, e: &mut Vec<Value>) {
        e.push(self.effect("retireAttempt"));
        self.step = "retry";
        self.bridge = "reconnecting";
        self.deadline = now + (1000u64 << self.retries.min(5)).min(30000) + jitter;
        self.retries = self.retries.saturating_add(1);
        e.push(self.timer("retry"));
    }
    pub fn execute(&mut self, c: &Value) -> Result<Value> {
        let op = text(c, "op")?;
        let mut effects = Vec::new();
        let result = match op {
            "snapshot" => {
                keys(c, &["op"])?;
                json!({"phase":self.phase,"queueCount":self.queue.len(),"selectionRevision":self.revision,"bridge":{"state":self.bridge,"generation":self.generation.to_string(),"attempt":self.attempt.to_string()}})
            }
            "activate" => {
                keys(c, &["op"])?;
                if self.phase != "starting" {
                    return Err("ESTATE");
                };
                self.phase = "running";
                Value::Null
            }
            "beginClose" => {
                keys(c, &["op"])?;
                if self.phase != "closing" && self.phase != "closed" {
                    self.phase = "closing";
                    next(&mut self.revision)?;
                    self.stop(&mut effects)?;
                    effects.push(json!({"type":"cancelSetup"}));
                    effects.push(json!({"type":"cancelPicker"}));
                }
                Value::Null
            }
            "finishClose" => {
                keys(c, &["op"])?;
                if self.phase != "closing" || !self.queue.is_empty() {
                    return Err("ESTATE");
                };
                self.phase = "closed";
                Value::Null
            }
            "admit" => {
                keys(c, &["op", "capacity"])?;
                let capacity = number(c, "capacity")?;
                if capacity == 0 || capacity > 24 {
                    return Err("EINPUT");
                };
                if self.phase == "closing"
                    || self.phase == "closed"
                    || self.queue.len() >= capacity as usize
                {
                    return Err("EBUSY");
                };
                next(&mut self.ticket)?;
                let ticket = self.ticket.to_string();
                self.queue.push_back(ticket.clone());
                if self.queue.len() == 1 {
                    effects.push(json!({"type":"runTicket","ticket":ticket}));
                }
                json!({"ticket":ticket})
            }
            "finish" => {
                keys(c, &["op", "ticket"])?;
                if self.queue.front().map(String::as_str) != Some(text(c, "ticket")?) {
                    return Err("ETICKET");
                };
                self.queue.pop_front();
                if let Some(ticket) = self.queue.front() {
                    effects.push(json!({"type":"runTicket","ticket":ticket}));
                } else {
                    effects.push(json!({"type":"drained"}));
                }
                Value::Null
            }
            "invalidateSelection" => {
                keys(c, &["op"])?;
                next(&mut self.revision)?;
                effects.push(json!({"type":"cancelSetup"}));
                effects.push(json!({"type":"cancelPicker"}));
                json!(self.revision)
            }
            "permitEffect" => {
                keys(c, &["op"])?;
                json!(self.phase == "running")
            }
            "bridgeStop" => {
                keys(c, &["op"])?;
                self.stop(&mut effects)?;
                Value::Null
            }
            "bridgeStart" => {
                keys(c, &["op", "hasIdentity", "now"])?;
                let now = number(c, "now")?;
                let identity = c["hasIdentity"].as_bool().ok_or("EINPUT")?;
                if self.phase != "running" {
                    return Err("ECLOSING");
                };
                self.stop(&mut effects)?;
                self.retries = 0;
                if identity {
                    self.connect(now, &mut effects)?
                } else {
                    self.bridge = "not-configured";
                }
                Value::Null
            }
            "bridgeEvent" => {
                keys(
                    c,
                    &["op", "generation", "attempt", "event", "now", "jitter"],
                )?;
                let now = number(c, "now")?;
                let jitter = number(c, "jitter")?;
                if jitter > 499 {
                    return Err("EINPUT");
                };
                let event = text(c, "event")?;
                if ![
                    "prepared",
                    "failed",
                    "open",
                    "close",
                    "pong",
                    "connect",
                    "heartbeat",
                    "retry",
                ]
                .contains(&event)
                {
                    return Err("EINPUT");
                };
                if self.phase == "running" && self.current(c) && self.step != "stopped" {
                    match event {
                        "retry" if self.step == "retry" && now >= self.deadline => {
                            effects.push(self.effect("retireAttempt"));
                            self.connect(now, &mut effects)?;
                        }
                        "prepared" if self.step == "preparing" => {
                            if now >= self.deadline {
                                self.retry(now, jitter, &mut effects)
                            } else {
                                self.step = "connecting";
                                effects.push(self.effect("openSocket"));
                            }
                        }
                        "open" if self.step == "connecting" => {
                            if now >= self.deadline {
                                self.retry(now, jitter, &mut effects)
                            } else {
                                effects.push(self.effect("cancelTimers"));
                                self.step = "connected";
                                self.bridge = "connected";
                                self.retries = 0;
                                self.pong = now;
                                self.deadline = now + 25000;
                                effects.push(self.timer("heartbeat"));
                                effects.push(self.effect("publishMetadata"));
                            }
                        }
                        "pong" if self.step == "connected" => self.pong = now,
                        "heartbeat" if self.step == "connected" && now >= self.deadline => {
                            if now.saturating_sub(self.pong) > 65000 {
                                self.retry(now, jitter, &mut effects)
                            } else {
                                effects.push(self.effect("sendPing"));
                                self.deadline = now + 25000;
                                effects.push(self.timer("heartbeat"));
                            }
                        }
                        "connect"
                            if ["preparing", "connecting"].contains(&self.step)
                                && now >= self.deadline =>
                        {
                            self.retry(now, jitter, &mut effects)
                        }
                        "failed" | "close" if self.step != "retry" => {
                            self.retry(now, jitter, &mut effects)
                        }
                        _ => {}
                    }
                }
                Value::Null
            }
            "replyPermit" => {
                keys(c, &["op", "generation", "attempt", "open"])?;
                let open = c["open"].as_bool().ok_or("EINPUT")?;
                json!(open && self.live() && self.step == "connected" && self.current(c))
            }
            "bridgeCall" => {
                keys(c, &["op", "generation", "attempt", "id"])?;
                let id = text(c, "id")?;
                if id.len() != 36
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase() || b == b'-')
                {
                    return Err("EINPUT");
                };
                if !self.live() || self.step != "connected" || !self.current(c) {
                    json!("drop")
                } else if self.seen.iter().any(|s| s == id) {
                    json!("duplicate")
                } else {
                    self.seen.push_back(id.to_owned());
                    if self.seen.len() > 1000 {
                        self.seen.pop_front();
                    }
                    json!("execute")
                }
            }
            _ => return Err("EINPUT"),
        };
        Ok(json!({"result":result,"effects":effects}))
    }
}
pub fn dispatch(state: &mut State, bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() > FRAME_BYTES {
        return None;
    };
    let request: Value = serde_json::from_slice(bytes).ok()?;
    if keys(&request, &["v", "serial", "command"]).is_err()
        || request["v"] != 1
        || request["serial"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > SAFE)
    {
        return None;
    };
    let response = match state.execute(&request["command"]) {
        Ok(result) => json!({"v":1,"serial":request["serial"],"ok":true,"value":result}),
        Err(error) => json!({"v":1,"serial":request["serial"],"ok":false,"error":error}),
    };
    let bytes = serde_json::to_vec(&response).ok()?;
    (bytes.len() <= FRAME_BYTES).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(s: &mut State, v: Value) -> Value {
        s.execute(&v).unwrap()
    }
    #[test]
    fn fifo_close_and_once_finish() {
        let mut s = State::default();
        run(&mut s, json!({"op":"activate"}));
        for n in 1..=24 {
            assert_eq!(
                run(&mut s, json!({"op":"admit","capacity":24}))["result"]["ticket"],
                n.to_string()
            );
        }
        assert_eq!(
            s.execute(&json!({"op":"admit","capacity":24})),
            Err("EBUSY")
        );
        run(&mut s, json!({"op":"beginClose"}));
        for n in 1..=24 {
            run(&mut s, json!({"op":"finish","ticket":n.to_string()}));
        }
        assert_eq!(
            s.execute(&json!({"op":"finish","ticket":"24"})),
            Err("ETICKET")
        );
        run(&mut s, json!({"op":"finishClose"}));
        assert_eq!(s.phase, "closed");
    }
    fn event(s: &mut State, event: &str, now: u64) -> Value {
        run(
            s,
            json!({"op":"bridgeEvent","generation":s.generation.to_string(),"attempt":s.attempt.to_string(),"event":event,"now":now,"jitter":499}),
        )
    }
    #[test]
    fn deadline_retry_and_stale_attempt() {
        let mut s = State::default();
        run(&mut s, json!({"op":"activate"}));
        run(
            &mut s,
            json!({"op":"bridgeStart","hasIdentity":true,"now":0}),
        );
        event(&mut s, "connect", 14999);
        assert_eq!(s.step, "preparing");
        event(&mut s, "connect", 15000);
        assert_eq!(s.deadline, 16499);
        event(&mut s, "retry", 16499);
        assert_eq!(s.attempt, 2);
        let old = json!({"op":"bridgeEvent","generation":s.generation.to_string(),"attempt":"1","event":"open","now":16500,"jitter":0});
        assert!(run(&mut s, old)["effects"].as_array().unwrap().is_empty());
        event(&mut s, "prepared", 16500);
        event(&mut s, "open", 16501);
        event(&mut s, "heartbeat", 81501);
        assert_eq!(s.step, "connected");
        event(&mut s, "heartbeat", 106501);
        assert_eq!(s.step, "retry");
    }
    #[test]
    fn dedup_survives_stop_and_eviction() {
        let mut s = State::default();
        run(&mut s, json!({"op":"activate"}));
        for round in 0..2 {
            run(
                &mut s,
                json!({"op":"bridgeStart","hasIdentity":true,"now":0}),
            );
            event(&mut s, "prepared", 1);
            event(&mut s, "open", 2);
            let c = json!({"op":"bridgeCall","generation":s.generation.to_string(),"attempt":s.attempt.to_string(),"id":"00000000-0000-0000-0000-000000000000"});
            assert_eq!(
                run(&mut s, c)["result"],
                if round == 0 { "execute" } else { "duplicate" }
            );
            run(&mut s, json!({"op":"bridgeStop"}));
        }
        assert_eq!(s.seen.len(), 1);
    }
}
