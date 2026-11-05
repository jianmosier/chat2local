//! Transaction-local deterministic continuations. No storage or platform imports.
mod account;
mod basic;
mod common;
mod install;
mod instance;
mod onboarding;
pub mod values;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub use values::{Node, V};
pub const FRAME_BYTES: usize = 1_048_576;
const MAX_REFS: usize = 32768;
const NEW_BASE: u32 = 1_000_000;
const MAX_STEPS: usize = 16384;

#[derive(Debug)]
pub enum Stop {
    Need(Value),
    Business(String, u16),
    Invalid,
}
pub type Result<T> = std::result::Result<T, Stop>;
pub fn fail<T>(message: &str, status: u16) -> Result<T> {
    Err(Stop::Business(message.into(), status))
}
#[derive(Default)]
pub struct Engine {
    op: String,
    input: V,
    nodes: BTreeMap<u32, Node>,
    observed: Vec<(EffectKey, V)>,
    pending: Option<EffectKey>,
    ended: bool,
    projection_bytes: usize,
    observation_bytes: usize,
    records_checkpoint: Option<onboarding::RecordsCheckpoint>,
}
#[derive(PartialEq)]
struct EffectKey {
    effect: Value,
    graph: [u8; 32],
}
fn unsigned_effect_numbers(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.is_u64(),
        Value::Array(values) => values.iter().all(unsigned_effect_numbers),
        Value::Object(values) => values.values().all(unsigned_effect_numbers),
        _ => true,
    }
}
pub struct Context<'a> {
    nodes: BTreeMap<u32, Node>,
    original: &'a BTreeMap<u32, Node>,
    observed: &'a [(EffectKey, V)],
    graph_fingerprint: Option<[u8; 32]>,
    cursor: usize,
    read_id: usize,
    patches: Vec<Value>,
    next: u32,
    pub branch: String,
    records_checkpoint: Option<onboarding::RecordsCheckpoint>,
}
impl<'a> Context<'a> {
    fn node(&self, id: &u32) -> Option<&Node> {
        self.nodes.get(id).or_else(|| self.original.get(id))
    }
    pub fn get(&self, value: &V, field: &str) -> V {
        match value {
            V::Ref(id) => self
                .node(id)
                .and_then(|n| {
                    n.props
                        .iter()
                        .find(|(k, _)| k == field)
                        .map(|(_, v)| v.clone())
                })
                .unwrap_or_default(),
            _ => V::Undefined,
        }
    }
    /// Non-optional JS property access. Array filter/map callers skip Hole first.
    pub fn property(&self, value: &V, field: &str) -> Result<V> {
        if matches!(value, V::Undefined | V::Null | V::Hole) {
            return Err(Stop::Invalid);
        }
        Ok(self.get(value, field))
    }
    pub fn array(&self, v: &V) -> Result<Vec<V>> {
        match v {
            V::Ref(id) => self
                .node(id)
                .filter(|n| n.kind == "array")
                .map(|n| n.items.clone())
                .ok_or(Stop::Invalid),
            _ => Err(Stop::Invalid),
        }
    }
    pub fn object(&mut self, entries: Vec<(&str, V)>) -> V {
        let props: Vec<(String, V)> = entries.into_iter().map(|(k, v)| (k.into(), v)).collect();
        self.create(Node {
            id: 0,
            kind: "object".into(),
            keys: props
                .iter()
                .map(|(k, _)| k.encode_utf16().collect())
                .collect(),
            props,
            items: vec![],
            base: None,
        })
    }
    pub fn list(&mut self, items: Vec<V>) -> V {
        self.create(Node {
            id: 0,
            kind: "array".into(),
            props: vec![],
            keys: vec![],
            items,
            base: None,
        })
    }
    fn create(&mut self, mut node: Node) -> V {
        self.graph_fingerprint = None;
        self.next += 1;
        node.id = self.next;
        self.nodes.insert(node.id, node);
        V::Ref(self.next)
    }
    pub fn spread(&mut self, base: &V, entries: Vec<(&str, V)>) -> Result<V> {
        let V::Ref(id) = base else {
            return Err(Stop::Invalid);
        };
        let mut node = self.node(id).cloned().ok_or(Stop::Invalid)?;
        if node.kind != "object" {
            return Err(Stop::Invalid);
        }
        node.base = Some(*id);
        let out = self.create(node);
        for (key, value) in entries {
            self.set(&out, key, value)?;
        }
        Ok(out)
    }
    pub fn set(&mut self, target: &V, field: &str, value: V) -> Result<()> {
        self.graph_fingerprint = None;
        let V::Ref(id) = target else {
            return Err(Stop::Invalid);
        };
        if !self.nodes.contains_key(id) {
            self.nodes
                .insert(*id, self.original.get(id).cloned().ok_or(Stop::Invalid)?);
        }
        let node = self.nodes.get_mut(id).ok_or(Stop::Invalid)?;
        if node.kind != "object" {
            return Err(Stop::Invalid);
        }
        if let Some((_, old)) = node.props.iter_mut().find(|(k, _)| k == field) {
            *old = value.clone()
        } else {
            node.props.push((field.into(), value.clone()));
            node.keys.push(field.encode_utf16().collect());
        }
        if self.original.contains_key(id) {
            self.patches
                .push(json!({"target":id,"field":field,"value":value}));
        }
        Ok(())
    }
    pub fn exact(&self, value: &V, fields: &[&str]) -> Result<()> {
        let V::Ref(id) = value else {
            return fail("Invalid connection fields.", 400);
        };
        let node = self.node(id).ok_or(Stop::Invalid)?;
        if node.kind != "object"
            || node.keys.iter().any(|k| {
                !fields
                    .iter()
                    .any(|s| s.encode_utf16().eq(k.iter().copied()))
            })
        {
            return fail("Invalid connection fields.", 400);
        }
        Ok(())
    }
    fn recipe(&self) -> Value {
        json!({"nodes":self.nodes.range(NEW_BASE..).map(|(_,n)|n).collect::<Vec<_>>(),"patches":self.patches})
    }
    fn effect(&mut self, mut effect: Value) -> Result<V> {
        if self.cursor >= MAX_STEPS || self.nodes.len() + self.original.len() > MAX_REFS * 2 {
            return Err(Stop::Invalid);
        }
        if matches!(effect["type"].as_str(), Some("get" | "list")) {
            self.read_id += 1;
            effect["readId"] = json!(self.read_id);
        }
        // Effect JSON numbers are IDs/limits/UTF-16 units. Business numbers
        // retain their exact string tag, including negative zero.
        if !unsigned_effect_numbers(&effect) {
            return Err(Stop::Invalid);
        }
        let graph = match self.graph_fingerprint {
            Some(value) => value,
            None => {
                let value =
                    Sha256::digest(serde_json::to_vec(&self.recipe()).map_err(|_| Stop::Invalid)?)
                        .into();
                self.graph_fingerprint = Some(value);
                value
            }
        };
        // Exact effect equality avoids re-encoding every prior occurrence. The
        // graph digest is invalidated on every construction and patch.
        let fingerprint = EffectKey {
            effect: effect.clone(),
            graph,
        };
        let slot = self.cursor;
        self.cursor += 1;
        if let Some((old, value)) = self.observed.get(slot) {
            if old != &fingerprint {
                return Err(Stop::Invalid);
            }
            return Ok(value.clone());
        }
        Err(Stop::Need(
            json!({"kind":"need","seq":slot+1,"effect":effect,"graph":self.recipe()}),
        ))
    }
    pub fn read(&mut self, key: String) -> Result<V> {
        self.effect(json!({"type":"get","key":key}))
    }
    pub fn rows(&mut self, prefix: &str, limit: usize) -> Result<Vec<V>> {
        let v = self.rows_ref(prefix, limit)?;
        self.array(&v)
    }
    pub fn rows_ref(&mut self, prefix: &str, limit: usize) -> Result<V> {
        self.effect(json!({"type":"list","prefix":prefix,"limit":limit}))
    }
    pub fn put(&mut self, key: String, value: V) -> Result<()> {
        self.effect(json!({"type":"put","key":key,"value":value}))?;
        Ok(())
    }
    pub fn delete(&mut self, key: String) -> Result<()> {
        self.effect(json!({"type":"delete","key":key}))?;
        Ok(())
    }
    pub fn delete_many(&mut self, keys: Vec<String>) -> Result<()> {
        for part in keys.chunks(128) {
            self.effect(json!({"type":"deleteMany","keys":part}))?;
        }
        Ok(())
    }
    pub fn now(&mut self) -> Result<f64> {
        Ok(self.effect(json!({"type":"now"}))?.number())
    }
    pub fn compute(&mut self, kind: &str, value: V) -> Result<V> {
        self.effect(json!({"type":"compute","kind":kind,"value":value}))
    }
    pub fn random(&mut self, kind: &str) -> Result<V> {
        self.effect(json!({"type":"random","kind":kind}))
    }
    pub fn http(&mut self, status: u16, body: V, headers: V) -> V {
        self.object(vec![
            ("httpStatus", V::num(status as f64)),
            ("body", body),
            ("headers", headers),
        ])
    }
    pub fn ok(&mut self) -> V {
        let body = self.object(vec![("ok", V::Bool(true))]);
        self.http(200, body, V::Null)
    }
    pub fn reject(&mut self, status: u16, message: &str) -> V {
        let body = self.object(vec![("error", V::str(message))]);
        self.http(status, body, V::Null)
    }
}
impl Engine {
    fn run(&mut self) -> Result<Value> {
        let mut cx = Context {
            nodes: BTreeMap::new(),
            original: &self.nodes,
            observed: &self.observed,
            graph_fingerprint: None,
            cursor: 0,
            read_id: 0,
            patches: vec![],
            next: NEW_BASE,
            branch: String::new(),
            records_checkpoint: self.records_checkpoint.take(),
        };
        let outcome = if self.op.starts_with("account.") {
            account::execute(&mut cx, &self.op, &self.input)
        } else if self.op.starts_with("onboarding.") {
            onboarding::execute(&mut cx, &self.op, &self.input)
        } else if self.op.starts_with("instance.") {
            instance::execute(&mut cx, &self.op, &self.input)
        } else if self.op.starts_with("install.") {
            install::execute(&mut cx, &self.op, &self.input)
        } else {
            basic::execute(&mut cx, &self.op, &self.input)
        };
        self.records_checkpoint = cx.records_checkpoint.take();
        match outcome {
            Ok(value) => {
                if cx.cursor != self.observed.len() {
                    return Err(Stop::Invalid);
                }
                self.ended = true;
                Ok(
                    json!({"kind":"complete","value":value,"graph":cx.recipe(),"decision":{"op":self.op,"branch":cx.branch,"outcome":"normal"}}),
                )
            }
            Err(Stop::Need(request)) => {
                let graph = Sha256::digest(
                    serde_json::to_vec(&request["graph"]).map_err(|_| Stop::Invalid)?,
                )
                .into();
                self.pending = Some(EffectKey {
                    effect: request["effect"].clone(),
                    graph,
                });
                Ok(request)
            }
            Err(Stop::Business(message, status)) => {
                self.ended = true;
                Ok(
                    json!({"kind":"abort","message":message,"status":status,"decision":{"op":self.op,"branch":cx.branch,"outcome":"abort"}}),
                )
            }
            Err(Stop::Invalid) => Err(Stop::Invalid),
        }
    }
    pub fn command(&mut self, c: Value) -> Result<Value> {
        match c["type"].as_str() {
            Some("init") if self.op.is_empty() => {
                self.op = c["op"].as_str().ok_or(Stop::Invalid)?.into();
                self.input =
                    serde_json::from_value(c["input"].clone()).map_err(|_| Stop::Invalid)?;
                Ok(json!({"kind":"ack"}))
            }
            Some("graph") if !self.ended => {
                self.projection_bytes += serde_json::to_vec(&c).map_err(|_| Stop::Invalid)?.len();
                if self.projection_bytes > 16 * FRAME_BYTES {
                    return Err(Stop::Invalid);
                }
                let nodes: Vec<Node> =
                    serde_json::from_value(c["nodes"].clone()).map_err(|_| Stop::Invalid)?;
                for n in nodes {
                    if n.id == 0
                        || n.id >= NEW_BASE
                        || self.nodes.contains_key(&n.id)
                        || self.nodes.len() >= MAX_REFS
                        || !matches!(n.kind.as_str(), "object" | "array" | "opaque")
                        || n.base.is_some()
                    {
                        return Err(Stop::Invalid);
                    }
                    self.nodes.insert(n.id, n);
                }
                Ok(json!({"kind":"ack"}))
            }
            Some("run")
                if !self.op.is_empty()
                    && !self.ended
                    && self.pending.is_none()
                    && self.observed.is_empty() =>
            {
                self.run()
            }
            Some("resume") if !self.ended && self.pending.is_some() => {
                if c["seq"].as_u64() != Some(self.observed.len() as u64 + 1) {
                    return Err(Stop::Invalid);
                }
                let value =
                    serde_json::from_value(c["value"].clone()).map_err(|_| Stop::Invalid)?;
                self.observation_bytes +=
                    serde_json::to_vec(&self.pending.as_ref().ok_or(Stop::Invalid)?.effect)
                        .map_err(|_| Stop::Invalid)?
                        .len()
                        + serde_json::to_vec(&value).map_err(|_| Stop::Invalid)?.len()
                        + 32;
                if self.observation_bytes > 8 * FRAME_BYTES {
                    return Err(Stop::Invalid);
                }
                self.observed
                    .push((self.pending.take().ok_or(Stop::Invalid)?, value));
                self.run()
            }
            _ => Err(Stop::Invalid),
        }
    }
}
pub fn dispatch(state: &mut Engine, bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() > FRAME_BYTES {
        return None;
    }
    let request: Value = serde_json::from_slice(bytes).ok()?;
    if request["v"] != 1 {
        return None;
    }
    let serial = request["serial"].as_u64()?;
    let result = state.command(request["command"].clone()).ok()?;
    let out = serde_json::to_vec(&json!({"v":1,"serial":serial,"result":result})).ok()?;
    (out.len() <= FRAME_BYTES).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn enroll() -> Engine {
        let mut engine = Engine::default();
        let node = |id, props: Vec<(&str, V)>| Node {
            id,
            kind: "object".into(),
            keys: props
                .iter()
                .map(|(k, _)| k.encode_utf16().collect())
                .collect(),
            props: props.into_iter().map(|(k, v)| (k.into(), v)).collect(),
            items: vec![],
            base: None,
        };
        engine.command(json!({"type":"graph","nodes":[node(1,vec![("value",V::Ref(2))]),node(2,vec![("deviceId",V::str(&"a".repeat(32)))])]})).unwrap();
        engine
            .command(json!({"type":"init","op":"registry.enroll","input":V::Ref(1)}))
            .unwrap();
        engine
    }
    fn resume(engine: &mut Engine, seq: usize, value: V) -> Value {
        engine
            .command(json!({"type":"resume","seq":seq,"value":value}))
            .unwrap()
    }
    #[test]
    fn enrollment_continuation_binds_order_and_finishes_once() {
        let mut engine = enroll();
        let first = engine.command(json!({"type":"run"})).unwrap();
        assert_eq!(first["effect"]["key"], "deviceCount");
        assert!(engine.command(json!({"type":"run"})).is_err());
        assert!(
            engine
                .command(json!({"type":"resume","seq":2,"value":V::Undefined}))
                .is_err()
        );
        let second = resume(&mut engine, 1, V::num(0.0));
        assert_eq!(second["effect"]["readId"], 2);
        assert_eq!(second["seq"], 2);
        let third = resume(&mut engine, 2, V::Undefined);
        assert_eq!(third["effect"]["type"], "put");
        assert_eq!(third["effect"]["key"], "deviceCount");
        assert_eq!(
            resume(&mut engine, 3, V::Undefined)["effect"]["key"],
            format!("device:{}", "a".repeat(32))
        );
        let done = resume(&mut engine, 4, V::Undefined);
        assert_eq!(done["kind"], "complete");
        assert_eq!(done["decision"]["branch"], "created");
        assert!(
            engine
                .command(json!({"type":"resume","seq":5,"value":V::Undefined}))
                .is_err()
        );
        let mut fresh = enroll();
        assert_eq!(fresh.command(json!({"type":"run"})).unwrap()["seq"], 1);
    }
    #[test]
    fn malformed_known_counter_and_changed_effect_prefix_fail_closed() {
        for value in [V::str("0x64"), V::str(" 100 "), V::BigInt, V::num(f64::NAN)] {
            let mut e = enroll();
            e.command(json!({"type":"run"})).unwrap();
            assert!(
                e.command(json!({"type":"resume","seq":1,"value":value}))
                    .is_err()
            );
        }
        let mut e = enroll();
        e.command(json!({"type":"run"})).unwrap();
        resume(&mut e, 1, V::num(0.0));
        e.observed[0].0.graph = [0; 32];
        assert!(
            e.command(json!({"type":"resume","seq":2,"value":V::Undefined}))
                .is_err()
        );
    }
    #[test]
    fn effect_number_domain_preserves_signed_zero_and_string_order() {
        assert!(!unsigned_effect_numbers(&json!({"value":-0.0})));
        assert!(!unsigned_effect_numbers(&json!({"value":1.0})));
        assert!(unsigned_effect_numbers(
            &json!({"readId":1,"value":{"t":"n","v":"-0"}})
        ));
        assert_ne!(
            json!({"value":{"t":"n","v":"-0"}}),
            json!({"value":{"t":"n","v":"0"}})
        );
        assert_ne!(json!(["a", "b"]), json!(["b", "a"]));
    }
    #[test]
    fn nullish_nonoptional_access_is_not_missing_property_and_utf16_is_lossless() {
        let nodes = BTreeMap::new();
        let cx = Context {
            nodes: nodes.clone(),
            original: &nodes,
            observed: &[],
            graph_fingerprint: None,
            records_checkpoint: None,
            cursor: 0,
            read_id: 0,
            patches: vec![],
            next: NEW_BASE,
            branch: String::new(),
        };
        for value in [V::Null, V::Undefined, V::Hole] {
            assert!(cx.property(&value, "until").is_err())
        }
        assert_eq!(cx.property(&V::num(123.0), "until").unwrap(), V::Undefined);
        let value = V::String(vec![0xd800, 0, 0xfeff, 0xdc00]);
        assert_eq!(
            serde_json::from_slice::<V>(&serde_json::to_vec(&value).unwrap()).unwrap(),
            value
        );
    }
}
