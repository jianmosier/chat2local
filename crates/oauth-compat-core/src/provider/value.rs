//! Flat, lossless data transport. Never JSON.stringify application helper data.
use super::{Error, Result};
use crate::value::{self, LIMITS};
use chat2local_js_value_compat::{Document, Object, Value, ValueId};
use serde_json::{Value as Json, json};
use std::{cell::RefCell, rc::Rc};

#[derive(Clone)]
pub struct Arena(Rc<RefCell<Document>>);
#[derive(Clone)]
pub struct J {
    pub arena: Arena,
    pub id: ValueId,
}
impl Default for Arena {
    fn default() -> Self {
        Self(Rc::new(RefCell::new(Document::new().expect("arena"))))
    }
}
impl Arena {
    pub fn add(&self, value: Value) -> J {
        let id = self
            .0
            .borrow_mut()
            .add(value, LIMITS.nodes)
            .expect("resource limit");
        J {
            arena: self.clone(),
            id,
        }
    }
    pub fn undef(&self) -> J {
        self.add(Value::Undefined)
    }
    pub fn null(&self) -> J {
        self.add(Value::Null)
    }
    pub fn bool(&self, v: bool) -> J {
        self.add(Value::Bool(v))
    }
    pub fn num(&self, v: f64) -> J {
        self.add(Value::Number(v))
    }
    pub fn s(&self, v: impl AsRef<str>) -> J {
        self.units(v.as_ref().encode_utf16().collect())
    }
    pub fn units(&self, v: Vec<u16>) -> J {
        self.add(Value::String(v))
    }
    pub fn arr(&self, v: Vec<J>) -> J {
        self.add(Value::Array(v.into_iter().map(|v| v.id).collect()))
    }
    pub fn obj(&self, v: Vec<(&str, J)>) -> J {
        let o = self.add(Value::Object(Object::default()));
        for (k, v) in v {
            o.set(k, &v).expect("object");
        }
        o
    }
    pub fn parse(&self, text: &str) -> Result<J> {
        self.parse_units(&text.encode_utf16().collect::<Vec<_>>())
    }
    pub fn parse_units(&self, text: &[u16]) -> Result<J> {
        let d = Document::parse_utf16(text, LIMITS).map_err(|e| {
            if e.kind == chat2local_js_value_compat::ErrorKind::Syntax {
                Error::SyntaxJson(text.to_vec())
            } else {
                Error::Core
            }
        })?;
        let id = self
            .0
            .borrow_mut()
            .import(d, LIMITS.nodes)
            .map_err(|_| Error::Core)?;
        Ok(J {
            arena: self.clone(),
            id,
        })
    }
    pub fn decode(&self, wire: &Json) -> Result<J> {
        let nodes = wire
            .get("nodes")
            .and_then(Json::as_array)
            .ok_or(Error::Core)?;
        if nodes.len() > LIMITS.nodes {
            return Err(Error::Core);
        }
        let mut ids = Vec::with_capacity(nodes.len());
        for node in nodes {
            let tag = node.get(0).and_then(Json::as_str).ok_or(Error::Core)?;
            ids.push(match tag {
                "u" => self.undef(),
                "n" => self.null(),
                "b" => self.bool(node[1].as_bool().ok_or(Error::Core)?),
                "d" => self.num(f64::from_bits(
                    u64::from_str_radix(node[1].as_str().ok_or(Error::Core)?, 16)
                        .map_err(|_| Error::Core)?,
                )),
                "s" => {
                    self.units(serde_json::from_value(node[1].clone()).map_err(|_| Error::Core)?)
                }
                "a" => self.arr(vec![]),
                "A" => self.add(Value::SparseArray {
                    length: u32::try_from(node[1].as_u64().ok_or(Error::Core)?)
                        .map_err(|_| Error::Core)?,
                    properties: Object::default(),
                }),
                "o" => self.obj(vec![]),
                _ => return Err(Error::Core),
            });
        }
        for (i, node) in nodes.iter().enumerate() {
            match node[0].as_str() {
                Some("a") => {
                    for n in node[1].as_array().ok_or(Error::Core)? {
                        let item = ids
                            .get(n.as_u64().ok_or(Error::Core)? as usize)
                            .ok_or(Error::Core)?;
                        self.0
                            .borrow_mut()
                            .push(ids[i].id, item.id)
                            .map_err(|_| Error::Core)?;
                    }
                }
                Some("o" | "A") => {
                    let entries = if node[0] == "A" { &node[2] } else { &node[1] };
                    for entry in entries.as_array().ok_or(Error::Core)? {
                        let key: Vec<u16> =
                            serde_json::from_value(entry[0].clone()).map_err(|_| Error::Core)?;
                        let item = ids
                            .get(entry[1].as_u64().ok_or(Error::Core)? as usize)
                            .ok_or(Error::Core)?;
                        self.0
                            .borrow_mut()
                            .set_property(ids[i].id, key, item.id)
                            .map_err(|_| Error::Core)?;
                    }
                }
                _ => {}
            }
        }
        ids.get(wire["root"].as_u64().ok_or(Error::Core)? as usize)
            .cloned()
            .ok_or(Error::Core)
    }
}
impl J {
    pub fn val(&self) -> Value {
        self.arena
            .0
            .borrow()
            .value(self.id)
            .expect("owned value")
            .clone()
    }
    pub fn undefined(&self) -> bool {
        matches!(self.val(), Value::Undefined)
    }
    pub fn nullish(&self) -> bool {
        matches!(self.val(), Value::Undefined | Value::Null)
    }
    pub fn truth(&self) -> bool {
        value::truthy(&self.arena.0.borrow(), self.id).expect("owned value")
    }
    pub fn get(&self, k: &str) -> Result<J> {
        if let Value::SparseArray { length, .. } = self.val()
            && k == "length"
        {
            return Ok(self.arena.num(f64::from(length)));
        }
        if let Value::Array(items) = self.val() {
            if k == "length" {
                return Ok(self.arena.num(items.len() as f64));
            }
            if let Ok(index) = k.parse::<usize>()
                && index.to_string() == k
            {
                return Ok(items
                    .get(index)
                    .map(|id| J {
                        arena: self.arena.clone(),
                        id: *id,
                    })
                    .unwrap_or_else(|| self.arena.undef()));
            }
        }
        let d = self.arena.0.borrow();
        let id = value::property(&d, self.id, k).map_err(|_| {
            Error::normal("TypeError", "Cannot read properties of null or undefined")
        })?;
        drop(d);
        Ok(id
            .map(|id| J {
                arena: self.arena.clone(),
                id,
            })
            .unwrap_or_else(|| self.arena.undef()))
    }
    pub fn set(&self, k: &str, v: &J) -> Result<()> {
        self.arena
            .0
            .borrow_mut()
            .set_property(self.id, k.encode_utf16().collect(), v.id)
            .map_err(|_| Error::normal("TypeError", "Cannot create property"))
    }
    pub fn set_units(&self, k: Vec<u16>, v: &J) -> Result<()> {
        self.arena
            .0
            .borrow_mut()
            .set_property(self.id, k, v.id)
            .map_err(|_| Error::normal("TypeError", "Cannot create property"))
    }
    pub fn remove(&self, k: &str) -> Result<()> {
        self.arena
            .0
            .borrow_mut()
            .remove_property(self.id, &k.encode_utf16().collect::<Vec<_>>())
            .map(|_| ())
            .map_err(|_| Error::normal("TypeError", "Cannot delete property"))
    }
    pub fn string(&self) -> Result<Vec<u16>> {
        value::string(&self.arena.0.borrow(), Some(self.id))
            .map_err(|_| Error::normal("TypeError", "Cannot convert object to primitive value"))
    }
    pub fn text(&self) -> Result<String> {
        Ok(String::from_utf16_lossy(&self.string()?))
    }
    pub fn str(&self) -> Result<Vec<u16>> {
        if let Value::String(s) = self.val() {
            Ok(s)
        } else {
            Err(Error::normal("TypeError", "Expected string"))
        }
    }
    pub fn number(&self) -> Result<f64> {
        value::number(&self.arena.0.borrow(), Some(self.id))
            .map_err(|_| Error::normal("TypeError", "Cannot convert object to primitive value"))
    }
    pub fn array(&self) -> Result<Vec<J>> {
        match self.val() {
            Value::Array(v) => Ok(v
                .into_iter()
                .map(|id| J {
                    arena: self.arena.clone(),
                    id,
                })
                .collect()),
            Value::SparseArray { length, properties } => {
                // A dense temporary is only needed for index-based algorithms.
                // Keep its own budget independent of the graph node limit.
                const MAX_MATERIALIZED_ITEMS: usize = 1_000_000;
                let length = usize::try_from(length).map_err(|_| Error::Core)?;
                if length > MAX_MATERIALIZED_ITEMS
                    || length.checked_mul(std::mem::size_of::<J>()).is_none()
                {
                    return Err(Error::Core);
                }
                let missing = self.arena.undef();
                Ok((0..length)
                    .map(|i| {
                        let key: Vec<u16> = i.to_string().encode_utf16().collect();
                        properties
                            .get(&key)
                            .map(|id| J {
                                arena: self.arena.clone(),
                                id,
                            })
                            .unwrap_or_else(|| missing.clone())
                    })
                    .collect())
            }
            _ => Err(Error::normal("TypeError", "Expected array")),
        }
    }
    pub fn present_array(&self) -> Result<Vec<J>> {
        if let Value::SparseArray { length, properties } = self.val() {
            let mut values = properties
                .entries()
                .iter()
                .filter_map(|(key, id)| {
                    let s = String::from_utf16(key).ok()?;
                    let index = s.parse::<u32>().ok()?;
                    (index < length && index.to_string() == s).then_some((index, *id))
                })
                .collect::<Vec<_>>();
            values.sort_unstable_by_key(|(index, _)| *index);
            Ok(values
                .into_iter()
                .map(|(_, id)| J {
                    arena: self.arena.clone(),
                    id,
                })
                .collect())
        } else {
            self.array()
        }
    }
    pub fn entries(&self) -> Vec<(Vec<u16>, J)> {
        match self.val() {
            Value::Object(o) => o
                .entries()
                .iter()
                .map(|(k, id)| {
                    (
                        k.clone(),
                        J {
                            arena: self.arena.clone(),
                            id: *id,
                        },
                    )
                })
                .collect(),
            Value::String(s) => s
                .into_iter()
                .enumerate()
                .map(|(i, c)| {
                    (
                        i.to_string().encode_utf16().collect(),
                        self.arena.units(vec![c]),
                    )
                })
                .collect(),
            Value::Array(v) => v
                .into_iter()
                .enumerate()
                .map(|(i, id)| {
                    (
                        i.to_string().encode_utf16().collect(),
                        J {
                            arena: self.arena.clone(),
                            id,
                        },
                    )
                })
                .collect(),
            Value::SparseArray { properties, .. } => properties
                .entries()
                .iter()
                .map(|(k, id)| {
                    (
                        k.clone(),
                        J {
                            arena: self.arena.clone(),
                            id: *id,
                        },
                    )
                })
                .collect(),
            _ => vec![],
        }
    }
    pub fn spread(&self) -> Result<J> {
        let out = self.arena.obj(vec![]);
        for (k, v) in self.entries() {
            self.arena
                .0
                .borrow_mut()
                .set_property(out.id, k, v.id)
                .map_err(|_| Error::Core)?;
        }
        Ok(out)
    }
    pub fn eq(&self, other: &J) -> bool {
        match (self.val(), other.val()) {
            (Value::Undefined, Value::Undefined) | (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a), Value::Number(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            _ => self.id == other.id,
        }
    }
    pub fn is(&self, s: &str) -> bool {
        matches!(self.val(),Value::String(v) if v==s.encode_utf16().collect::<Vec<_>>())
    }
    pub fn json(&self) -> Result<Option<String>> {
        let mut d = self.arena.0.borrow_mut();
        d.set_root(self.id).map_err(|_| Error::Core)?;
        let result = d.stringify(LIMITS);
        drop(d);
        result.map_err(|e| {
            if e.kind == chat2local_js_value_compat::ErrorKind::Cycle {
                self.wire().map(Error::CycleJson).unwrap_or(Error::Core)
            } else {
                Error::Core
            }
        })
    }
    pub fn wire(&self) -> Result<Json> {
        let mut queue = vec![self.clone()];
        let mut nodes = vec![];
        let mut refs = std::collections::HashMap::new();
        refs.insert(format!("{:?}", self.id), 0usize);
        let mut reference = |j: J, q: &mut Vec<J>| {
            let key = format!("{:?}", j.id);
            *refs.entry(key).or_insert_with(|| {
                let n = q.len();
                q.push(j);
                n
            })
        };
        let mut i = 0;
        while i < queue.len() {
            let j = queue[i].clone();
            let n = match j.val() {
                Value::Undefined => json!(["u"]),
                Value::Null => json!(["n"]),
                Value::Bool(b) => json!(["b", b]),
                Value::Number(n) => json!(["d", format!("{:016x}", n.to_bits())]),
                Value::String(s) => json!(["s", s]),
                Value::Array(v) => {
                    let a = v
                        .into_iter()
                        .map(|id| {
                            reference(
                                J {
                                    arena: j.arena.clone(),
                                    id,
                                },
                                &mut queue,
                            )
                        })
                        .collect::<Vec<_>>();
                    json!(["a", a])
                }
                Value::SparseArray { length, properties } => {
                    let a = properties
                        .entries()
                        .iter()
                        .map(|(k, id)| {
                            json!([
                                k,
                                reference(
                                    J {
                                        arena: j.arena.clone(),
                                        id: *id
                                    },
                                    &mut queue
                                )
                            ])
                        })
                        .collect::<Vec<_>>();
                    json!(["A", length, a])
                }
                Value::Object(o) => {
                    let a = o
                        .entries()
                        .iter()
                        .map(|(k, id)| {
                            json!([
                                k,
                                reference(
                                    J {
                                        arena: j.arena.clone(),
                                        id: *id
                                    },
                                    &mut queue
                                )
                            ])
                        })
                        .collect::<Vec<_>>();
                    json!(["o", a])
                }
            };
            nodes.push(n);
            i += 1;
            if nodes.len() > LIMITS.nodes {
                return Err(Error::Core);
            }
        }
        Ok(json!({"root":0,"nodes":nodes}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_materialization_budget_is_separate_from_graph_size() {
        let arena = Arena::default();
        let sparse = arena.add(Value::SparseArray {
            length: 1_000_001,
            properties: Object::default(),
        });
        assert!(matches!(sparse.array(), Err(Error::Core)));
        assert_eq!(sparse.present_array().unwrap().len(), 0);
        assert_eq!(sparse.get("length").unwrap().number().unwrap(), 1_000_001.0);
        assert_eq!(arena.arr(vec![arena.null()]).array().unwrap().len(), 1);
    }
}
