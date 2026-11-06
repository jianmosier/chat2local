//! Small operations on the shared JavaScript-compatible document. Persisted
//! subtrees never pass through serde_json (which cannot retain lone surrogates).
use crate::{Error, Result, value};
use chat2local_js_value_compat::{Document, Value};
use serde_json::json;
pub struct Doc(pub Document);
impl Doc {
    pub fn parse(raw: &str) -> Result<Self> {
        Ok(Self(value::parse(raw.as_bytes())?))
    }
    pub fn json(v: serde_json::Value) -> Result<Self> {
        Self::parse(&v.to_string())
    }
    pub fn object() -> Result<Self> {
        Self::parse("{}")
    }
    pub fn copy(&self) -> Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }
    pub fn raw(&self) -> Result<String> {
        value::serialized(&self.0)
    }
    pub fn has(&self, k: &str) -> bool {
        value::prop(&self.0, k).is_some()
    }
    pub fn s(&self, k: &str) -> Option<String> {
        value::string(&self.0, value::prop(&self.0, k))
    }
    pub fn b(&self, k: &str) -> bool {
        value::boolean(&self.0, value::prop(&self.0, k)) == Some(true)
    }
    pub fn n(&self, k: &str) -> Option<f64> {
        value::number(&self.0, value::prop(&self.0, k))
    }
    pub fn req(&self, k: &str) -> Result<String> {
        self.s(k)
            .ok_or_else(|| Error::new(400, format!("Invalid {k}.")))
    }
    pub fn get(&self, k: &str) -> Result<Option<Self>> {
        value::prop(&self.0, k)
            .map(|v| Self::parse(&value::subtree(&self.0, v)?))
            .transpose()
    }
    pub fn need(&self, k: &str) -> Result<Self> {
        self.get(k)?
            .ok_or_else(|| Error::new(400, format!("Missing {k}.")))
    }
    pub fn items(&self) -> Result<Vec<Self>> {
        let Value::Array(items) = self.0.value(self.0.root())? else {
            return Err(Error::new(400, "Array required."));
        };
        items
            .iter()
            .map(|v| Self::parse(&value::subtree(&self.0, *v)?))
            .collect()
    }
    pub fn array(&self, k: &str) -> Result<Vec<Self>> {
        self.get(k)?
            .map(|v| v.items())
            .transpose()
            .map(Option::unwrap_or_default)
    }
    pub fn set(&mut self, k: &str, v: Self) -> Result<()> {
        let id = self.0.import(v.0, usize::MAX)?;
        self.0
            .set_property(self.0.root(), k.encode_utf16().collect(), id)?;
        Ok(())
    }
    pub fn put(&mut self, k: &str, v: serde_json::Value) -> Result<()> {
        self.set(k, Self::json(v)?)
    }
    pub fn del(&mut self, k: &str) -> Result<()> {
        value::remove(&mut self.0, k)
    }
    pub fn list(items: Vec<Self>) -> Result<Self> {
        let mut d = Self::parse("[]")?;
        for item in items {
            let id = d.0.import(item.0, usize::MAX)?;
            d.0.push(d.0.root(), id)?;
        }
        Ok(d)
    }
    pub fn fields(&self, keys: &[&str]) -> Result<()> {
        value::fields(&self.0, keys)
    }
    pub fn mode(&self) -> Result<String> {
        crate::root_mode(&self.0, self.0.root())
    }
    pub fn permission(&mut self, mode: &str) -> Result<()> {
        if !["read-only", "review", "direct"].contains(&mode) {
            return Err(Error::new(400, "Invalid permission mode."));
        }
        self.put("write", json!(mode != "read-only"))?;
        self.put("writeMode", json!(mode))
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(openssl::sha::sha256(self.raw()?.as_bytes())))
    }
}
pub fn hex_id(v: &str, n: usize) -> bool {
    v.len() == n
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn id(d: &Doc, k: &str, n: usize) -> Result<String> {
    let s = d.req(k)?;
    if !hex_id(&s, n) {
        return Err(Error::new(400, format!("Invalid {k}.")));
    }
    Ok(s)
}
pub fn scopes(d: &Doc) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for item in d.items()? {
        let s = value::string(&item.0, Some(item.0.root()))
            .ok_or_else(|| Error::new(400, "Invalid scopes."))?;
        if ![
            "files:read",
            "files:write",
            "files:propose",
            "terminal:execute",
        ]
        .contains(&s.as_str())
            || out.contains(&s)
        {
            return Err(Error::new(400, "Invalid scopes."));
        }
        out.push(s);
    }
    if out.len() > 4 || !out.iter().any(|s| s == "files:read") {
        return Err(Error::new(400, "Invalid scopes."));
    }
    out.sort();
    Ok(out)
}
pub fn shares(d: &Doc) -> Result<Doc> {
    let mut items = d.items()?;
    if items.is_empty() || items.len() > 50 {
        return Err(Error::new(400, "Invalid shared folders."));
    }
    let mut seen = std::collections::HashSet::new();
    for v in &items {
        v.fields(&["rootId", "mode"])?;
        let id = v.req("rootId")?;
        if id.is_empty()
            || id.len() > 80
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || !seen.insert(id)
            || !matches!(
                v.s("mode").as_deref(),
                Some("read-only" | "review" | "direct")
            )
        {
            return Err(Error::new(400, "Invalid shared folders."));
        }
    }
    items.sort_by_key(|v| v.s("rootId"));
    Doc::list(
        items
            .into_iter()
            .map(|v| {
                let mut canonical = Doc::object()?;
                canonical.set("rootId", v.need("rootId")?)?;
                canonical.set("mode", v.need("mode")?)?;
                Ok(canonical)
            })
            .collect::<Result<_>>()?,
    )
}
pub fn permitted(local: &str, remote: &str, scopes: &[String]) -> &'static str {
    if local == "read-only" || remote == "read-only" {
        "read-only"
    } else if local == "direct" && remote == "direct" && scopes.iter().any(|s| s == "files:write") {
        "direct"
    } else if scopes.iter().any(|s| s == "files:propose") {
        "review"
    } else {
        "read-only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipts_compare_checked_fields_independently_of_object_property_order() {
        let left = Doc::parse(r#"[{"mode":"direct","rootId":"first"}]"#).unwrap();
        let right = Doc::parse(r#"[{"rootId":"first","mode":"direct"}]"#).unwrap();
        assert_eq!(
            shares(&left).unwrap().raw().unwrap(),
            shares(&right).unwrap().raw().unwrap()
        );
        assert!(
            shares(&Doc::parse(r#"[{"rootId":"first","mode":"direct","extra":true}]"#).unwrap())
                .is_err()
        );
    }
}
