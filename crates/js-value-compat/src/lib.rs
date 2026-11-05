//! JavaScript JSON data, without a JavaScript runtime or a recursive value tree.
//!
//! This covers JSON data and internal undefined/array holes, not getters, toJSON,
//! replacers, prototypes, BigInt or the separate Durable Object structured-clone
//! protocol. Limits belong to the caller. Refusal is never a missing document.
mod parse;
mod stringify;
use std::sync::atomic::{AtomicU64, Ordering};

pub type JsString = Vec<u16>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueId {
    owner: u64,
    index: usize,
}

#[derive(Clone, Debug)]
pub enum Value {
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(JsString),
    Array(Vec<ValueId>),
    SparseArray { length: u32, properties: Object },
    Object(Object),
}

/// Stored insertion order is independent of integer-index enumeration order.
#[derive(Clone, Debug, Default)]
pub struct Object {
    owner: Option<u64>,
    entries: Vec<(JsString, ValueId)>,
    indices: std::collections::HashMap<JsString, usize>,
}

impl Object {
    pub fn entries(&self) -> &[(JsString, ValueId)] {
        &self.entries
    }
    pub fn get(&self, key: &[u16]) -> Option<ValueId> {
        self.indices.get(key).map(|index| self.entries[*index].1)
    }
    fn set(&mut self, key: JsString, value: ValueId) {
        if let Some(index) = self.indices.get(&key) {
            self.entries[*index].1 = value;
        } else {
            self.indices.insert(key.clone(), self.entries.len());
            self.entries.push((key, value));
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub input_units: usize,
    pub nodes: usize,
    pub depth: usize,
    pub output_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Syntax,
    Limit,
    InvalidReference,
    WrongType,
    Cycle,
    OwnerExhausted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    /// UTF-16 input offset when parsing, otherwise zero.
    pub offset: usize,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON compatibility {:?} at {}", self.kind, self.offset)
    }
}
impl std::error::Error for Error {}
fn error(kind: ErrorKind) -> Error {
    Error { kind, offset: 0 }
}

/// Flat storage makes parse, stringify, cloning and destruction stack-safe.
#[derive(Debug)]
pub struct Document {
    owner: u64,
    nodes: Vec<Value>,
    root: ValueId,
}

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
fn next_owner(counter: &AtomicU64) -> Result<u64, Error> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| error(ErrorKind::OwnerExhausted))
}
impl Document {
    pub fn new() -> Result<Self, Error> {
        let owner = next_owner(&NEXT_OWNER)?;
        Ok(Self {
            owner,
            nodes: vec![Value::Undefined],
            root: ValueId { owner, index: 0 },
        })
    }
    /// An independent arena: even pre-existing source IDs cannot address it.
    /// Rebinding is iterative and preserves graph aliases and cycles internally.
    pub fn try_clone(&self) -> Result<Self, Error> {
        let owner = next_owner(&NEXT_OWNER)?;
        let mut nodes = self.nodes.clone();
        for node in &mut nodes {
            Self::rebind(node, owner, 0);
        }
        Ok(Self {
            owner,
            nodes,
            root: ValueId {
                owner,
                index: self.root.index,
            },
        })
    }
    pub fn root(&self) -> ValueId {
        self.root
    }
    pub fn value(&self, id: ValueId) -> Result<&Value, Error> {
        self.check(id)?;
        Ok(&self.nodes[id.index])
    }
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    pub fn set_root(&mut self, id: ValueId) -> Result<(), Error> {
        self.check(id)?;
        self.root = id;
        Ok(())
    }
    fn check(&self, id: ValueId) -> Result<(), Error> {
        if id.owner == self.owner && id.index < self.nodes.len() {
            Ok(())
        } else {
            Err(error(ErrorKind::InvalidReference))
        }
    }
    pub fn add(&mut self, mut value: Value, max_nodes: usize) -> Result<ValueId, Error> {
        if self.nodes.len() >= max_nodes {
            return Err(error(ErrorKind::Limit));
        }
        match &mut value {
            Value::Array(items) => {
                for item in items {
                    self.check(*item)?;
                }
            }
            Value::Object(object) => {
                if object.owner.is_some_and(|owner| owner != self.owner) {
                    return Err(error(ErrorKind::InvalidReference));
                }
                for (_, item) in object.entries() {
                    self.check(*item)?;
                }
                object.owner = Some(self.owner);
            }
            Value::SparseArray { properties, .. } => {
                if properties.owner.is_some_and(|owner| owner != self.owner) {
                    return Err(error(ErrorKind::InvalidReference));
                }
                for (_, item) in properties.entries() {
                    self.check(*item)?;
                }
                properties.owner = Some(self.owner);
            }
            _ => {}
        }
        let id = ValueId {
            owner: self.owner,
            index: self.nodes.len(),
        };
        self.nodes.push(value);
        Ok(id)
    }
    pub fn get_property(&self, object: ValueId, key: &[u16]) -> Result<Option<ValueId>, Error> {
        match self.value(object)? {
            Value::Object(value) => Ok(value.get(key)),
            Value::SparseArray { properties, .. } => Ok(properties.get(key)),
            _ => Err(error(ErrorKind::WrongType)),
        }
    }
    pub fn set_property(
        &mut self,
        object: ValueId,
        key: JsString,
        value: ValueId,
    ) -> Result<(), Error> {
        self.check(value)?;
        self.check(object)?;
        match self.nodes.get_mut(object.index) {
            Some(Value::Object(target)) => {
                target.set(key, value);
                Ok(())
            }
            Some(Value::SparseArray { length, properties }) => {
                if let Some(index) = array_index(&key)
                    && index >= *length
                {
                    return Err(error(ErrorKind::WrongType));
                }
                properties.set(key, value);
                Ok(())
            }
            _ => Err(error(ErrorKind::WrongType)),
        }
    }
    pub fn remove_property(&mut self, object: ValueId, key: &[u16]) -> Result<bool, Error> {
        self.check(object)?;
        match self.nodes.get_mut(object.index) {
            Some(Value::Object(target)) => {
                if let Some(index) = target.indices.remove(key) {
                    target.entries.remove(index);
                    for (index, (key, _)) in target.entries.iter().enumerate().skip(index) {
                        *target.indices.get_mut(key).unwrap() = index;
                    }
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(error(ErrorKind::WrongType)),
        }
    }
    pub fn push(&mut self, array: ValueId, value: ValueId) -> Result<(), Error> {
        self.check(value)?;
        self.check(array)?;
        match self.nodes.get_mut(array.index) {
            Some(Value::Array(items)) => {
                items.push(value);
                Ok(())
            }
            _ => Err(error(ErrorKind::WrongType)),
        }
    }
    /// Import a document without walking a recursive tree or changing aliases.
    pub fn import(&mut self, other: Document, max_nodes: usize) -> Result<ValueId, Error> {
        let offset = self.nodes.len();
        if offset
            .checked_add(other.nodes.len())
            .is_none_or(|n| n > max_nodes)
        {
            return Err(error(ErrorKind::Limit));
        }
        for mut node in other.nodes {
            Self::rebind(&mut node, self.owner, offset);
            self.nodes.push(node);
        }
        Ok(ValueId {
            owner: self.owner,
            index: other.root.index + offset,
        })
    }
    fn rebind(node: &mut Value, owner: u64, offset: usize) {
        let rebind = |id: &mut ValueId| {
            id.owner = owner;
            id.index += offset;
        };
        match node {
            Value::Array(items) => {
                for item in items {
                    rebind(item);
                }
            }
            Value::Object(object) => {
                object.owner = Some(owner);
                for (_, item) in &mut object.entries {
                    rebind(item);
                }
            }
            Value::SparseArray { properties, .. } => {
                properties.owner = Some(owner);
                for (_, item) in &mut properties.entries {
                    rebind(item);
                }
            }
            _ => {}
        }
    }
    pub fn parse_utf16(input: &[u16], limits: Limits) -> Result<Self, Error> {
        parse::parse(input, limits)
    }
    /// Input is already decoded Unicode. Byte-to-string replacement/fatal policy
    /// belongs to the host; this never silently replaces invalid UTF-8 bytes.
    pub fn parse_str(input: &str, limits: Limits) -> Result<Self, Error> {
        if input.len() / 3 > limits.input_units {
            return Err(error(ErrorKind::Limit));
        }
        let units: Vec<u16> = input.encode_utf16().collect();
        Self::parse_utf16(&units, limits)
    }
    /// None corresponds to JSON.stringify(undefined), not JSON null or missing.
    pub fn stringify(&self, limits: Limits) -> Result<Option<String>, Error> {
        stringify::stringify(self, limits)
    }
}

/// ECMAScript array-index property key: canonical decimal, 0 .. 2^32-2.
fn array_index(key: &[u16]) -> Option<u32> {
    if key.is_empty() || key.len() > 10 || (key.len() > 1 && key[0] == 48) {
        return None;
    }
    let mut value = 0u32;
    for unit in key {
        if !(48..=57).contains(unit) {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(*unit - 48))?;
    }
    (value != u32::MAX).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    const LIMITS: Limits = Limits {
        input_units: 1_000_000,
        nodes: 1_000_000,
        depth: 100_000,
        output_bytes: 4_000_000,
    };
    #[test]
    fn sparse_array_preserves_holes_properties_aliases_and_ownership() {
        let mut doc = Document::new().unwrap();
        let root = doc
            .add(
                Value::SparseArray {
                    length: 3,
                    properties: Object::default(),
                },
                LIMITS.nodes,
            )
            .unwrap();
        let child = doc.add(Value::String(vec![120]), LIMITS.nodes).unwrap();
        doc.set_property(root, vec![49], child).unwrap();
        doc.set_property(root, "01".encode_utf16().collect(), root)
            .unwrap();
        doc.set_root(root).unwrap();
        assert_eq!(doc.stringify(LIMITS).unwrap().unwrap(), "[null,\"x\",null]");
        let cloned = doc.try_clone().unwrap();
        assert_eq!(
            cloned.stringify(LIMITS).unwrap(),
            doc.stringify(LIMITS).unwrap()
        );
        let mut other = Document::new().unwrap();
        let imported = other.import(cloned, LIMITS.nodes).unwrap();
        assert_eq!(
            other
                .get_property(imported, &"01".encode_utf16().collect::<Vec<_>>())
                .unwrap(),
            Some(imported)
        );
        assert_eq!(
            other
                .set_property(imported, vec![51], imported)
                .unwrap_err()
                .kind,
            ErrorKind::WrongType
        );
        other.set_root(imported).unwrap();
        assert_eq!(
            other.stringify(LIMITS).unwrap().unwrap(),
            "[null,\"x\",null]"
        );
        let huge = other
            .add(
                Value::SparseArray {
                    length: u32::MAX,
                    properties: Object::default(),
                },
                LIMITS.nodes,
            )
            .unwrap();
        other.set_root(huge).unwrap();
        assert_eq!(other.stringify(LIMITS).unwrap_err().kind, ErrorKind::Limit);
    }
    #[test]
    fn duplicate_order_and_integer_keys() {
        let mut doc =
            Document::parse_str(r#"{"b":1,"10":2,"2":3,"b":4,"01":5,"__proto__":6}"#, LIMITS)
                .unwrap();
        assert_eq!(
            doc.stringify(LIMITS).unwrap().unwrap(),
            r#"{"2":3,"10":2,"b":4,"01":5,"__proto__":6}"#
        );
        let root = doc.root();
        doc.remove_property(root, &['b' as u16]).unwrap();
        let id = doc.add(Value::Null, LIMITS.nodes).unwrap();
        doc.set_property(root, vec!['b' as u16], id).unwrap();
        assert!(
            doc.stringify(LIMITS)
                .unwrap()
                .unwrap()
                .ends_with("\"b\":null}")
        );
    }
    #[test]
    fn surrogate_and_number_spelling() {
        let doc = Document::parse_str(
            r#"["\ud800","\ud83d\ude00",-0,1e400,9007199254740993,0.000001]"#,
            LIMITS,
        )
        .unwrap();
        assert_eq!(
            doc.stringify(LIMITS).unwrap().unwrap(),
            "[\"\\ud800\",\"😀\",0,null,9007199254740992,0.000001]"
        );
    }
    #[test]
    fn deep_data_is_iterative_including_drop() {
        let input = "[".repeat(20000) + "0" + &"]".repeat(20000);
        let doc = Document::parse_str(&input, LIMITS).unwrap();
        assert_eq!(doc.stringify(LIMITS).unwrap().unwrap(), input);
        let cloned = doc.try_clone().unwrap();
        assert_ne!(doc.root(), cloned.root());
        assert_eq!(cloned.stringify(LIMITS).unwrap().unwrap(), input);
    }
    #[test]
    fn undefined_cycle_and_resource_refusal_are_distinct() {
        let mut doc = Document::new().unwrap();
        assert_eq!(doc.stringify(LIMITS).unwrap(), None);
        let root = doc
            .add(Value::Object(Object::default()), LIMITS.nodes)
            .unwrap();
        doc.set_root(root).unwrap();
        doc.set_property(root, vec![120], root).unwrap();
        assert_eq!(doc.stringify(LIMITS).unwrap_err().kind, ErrorKind::Cycle);
        assert_eq!(
            Document::parse_str("[0]", Limits { depth: 0, ..LIMITS })
                .unwrap_err()
                .kind,
            ErrorKind::Limit
        );
        assert_eq!(
            Document::parse_str("[0,]", LIMITS).unwrap_err().kind,
            ErrorKind::Syntax
        );
    }
    #[test]
    fn foreign_ids_and_cloned_object_entries_never_alias() {
        let mut a = Document::parse_str(r#"{"x":1,"empty":{}}"#, LIMITS).unwrap();
        let mut b = Document::parse_str(r#"{"x":2,"empty":{}}"#, LIMITS).unwrap();
        let ax = a.get_property(a.root(), &[120]).unwrap().unwrap();
        let bx = b.get_property(b.root(), &[120]).unwrap().unwrap();
        assert_eq!(ax.index, bx.index);
        assert_ne!(ax.owner, bx.owner);
        assert_eq!(b.value(ax).unwrap_err().kind, ErrorKind::InvalidReference);
        assert_eq!(
            b.get_property(a.root(), &[120]).unwrap_err().kind,
            ErrorKind::InvalidReference
        );
        assert_eq!(
            b.set_root(a.root()).unwrap_err().kind,
            ErrorKind::InvalidReference
        );
        assert_eq!(
            b.set_property(b.root(), vec![120], ax).unwrap_err().kind,
            ErrorKind::InvalidReference
        );
        assert_eq!(
            b.set_property(a.root(), vec![120], bx).unwrap_err().kind,
            ErrorKind::InvalidReference
        );
        assert_eq!(
            b.remove_property(a.root(), &[120]).unwrap_err().kind,
            ErrorKind::InvalidReference
        );
        assert_eq!(
            b.add(Value::Array(vec![ax]), LIMITS.nodes)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidReference
        );
        let object = a.value(a.root()).unwrap().clone();
        let Value::Object(ref object_view) = object else {
            panic!("object");
        };
        for (_, entry) in object_view.entries() {
            assert_eq!(
                b.value(*entry).unwrap_err().kind,
                ErrorKind::InvalidReference
            );
        }
        assert_eq!(
            b.add(object, LIMITS.nodes).unwrap_err().kind,
            ErrorKind::InvalidReference
        );
        let empty = a
            .get_property(a.root(), &"empty".encode_utf16().collect::<Vec<_>>())
            .unwrap()
            .unwrap();
        assert_eq!(
            b.add(a.value(empty).unwrap().clone(), LIMITS.nodes)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidReference
        );
        let array = a.add(Value::Array(Vec::new()), LIMITS.nodes).unwrap();
        assert_eq!(
            b.push(array, bx).unwrap_err().kind,
            ErrorKind::InvalidReference
        );
        assert_eq!(
            a.push(array, bx).unwrap_err().kind,
            ErrorKind::InvalidReference
        );
        assert_eq!(
            b.stringify(LIMITS).unwrap().unwrap(),
            r#"{"x":2,"empty":{}}"#
        );
    }
    #[test]
    fn clone_has_fresh_owner_and_import_rebinds_shared_and_cyclic_graphs() {
        let mut original = Document::parse_str(r#"{"x":1}"#, LIMITS).unwrap();
        let mut cloned = original.try_clone().unwrap();
        assert_eq!(
            cloned.value(original.root()).unwrap_err().kind,
            ErrorKind::InvalidReference
        );
        let a = original.add(Value::Number(7.0), LIMITS.nodes).unwrap();
        let b = cloned.add(Value::Number(8.0), LIMITS.nodes).unwrap();
        assert_eq!(a.index, b.index);
        assert_eq!(
            cloned
                .set_property(cloned.root(), vec![120], a)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidReference
        );
        cloned.set_property(cloned.root(), vec![120], b).unwrap();
        assert_eq!(original.stringify(LIMITS).unwrap().unwrap(), r#"{"x":1}"#);
        assert_eq!(cloned.stringify(LIMITS).unwrap().unwrap(), r#"{"x":8}"#);
        let child = original.root();
        let shared = original
            .add(Value::Array(vec![child, child]), LIMITS.nodes)
            .unwrap();
        original.set_root(shared).unwrap();
        let mut destination = Document::new().unwrap();
        let imported = destination
            .import(original.try_clone().unwrap(), LIMITS.nodes)
            .unwrap();
        destination.set_root(imported).unwrap();
        let Value::Array(items) = destination.value(imported).unwrap() else {
            panic!("array");
        };
        assert_eq!(items[0], items[1]);
        assert_eq!(
            destination.stringify(LIMITS).unwrap().unwrap(),
            r#"[{"x":1},{"x":1}]"#
        );
        original.push(shared, shared).unwrap();
        let cyclic = original.try_clone().unwrap();
        assert_eq!(cyclic.stringify(LIMITS).unwrap_err().kind, ErrorKind::Cycle);
        let imported_cycle = destination.import(cyclic, LIMITS.nodes).unwrap();
        destination.set_root(imported_cycle).unwrap();
        assert_eq!(
            destination.stringify(LIMITS).unwrap_err().kind,
            ErrorKind::Cycle
        );
    }
    #[test]
    fn owner_exhaustion_is_explicit_and_does_not_wrap() {
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(next_owner(&counter).unwrap(), u64::MAX - 1);
        assert_eq!(
            next_owner(&counter).unwrap_err().kind,
            ErrorKind::OwnerExhausted
        );
        assert_eq!(
            next_owner(&counter).unwrap_err().kind,
            ErrorKind::OwnerExhausted
        );
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}
