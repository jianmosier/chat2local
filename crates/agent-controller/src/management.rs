use crate::{Error, Result, random, value};
use chat2local_js_value_compat::{Document, Value};
use chat2local_native_store::Store;
use sha2::{Digest, Sha256};
pub fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
fn valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn proof(cookie: &str) -> Option<&str> {
    let mut found = cookie
        .split(';')
        .map(str::trim)
        .filter_map(|s| s.strip_prefix("c2l_management="));
    let value = found.next()?;
    (found.next().is_none() && valid(value)).then_some(value)
}
pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as f64
}
pub struct Sessions {
    saved: Option<Document>,
}
impl Default for Sessions {
    fn default() -> Self {
        Self::new()
    }
}
impl Sessions {
    pub fn new() -> Self {
        Self { saved: None }
    }
    fn load(&mut self, store: &Store) -> Result<&Document> {
        if self.saved.is_none() {
            let saved = store
                .read_private_record("management-sessions")?
                .unwrap_or(value::parse(br#"{"version":1,"sessions":[]}"#)?);
            let sessions = value::array(&saved, value::prop(&saved, "sessions"))
                .ok_or_else(|| Error::new(400, "Invalid management sessions."))?;
            if value::number(&saved, value::prop(&saved, "version")) != Some(1.0)
                || sessions.len() > 16
                || sessions.iter().any(|id| {
                    !value::string(&saved, value::get(&saved, *id, "proofHash"))
                        .is_some_and(|s| valid(&s))
                        || !value::string(&saved, value::get(&saved, *id, "bindingHash"))
                            .is_some_and(|s| valid(&s))
                        || !value::number(&saved, value::get(&saved, *id, "expiresAt")).is_some_and(
                            |n| n.is_finite() && n.fract() == 0.0 && n.abs() <= 9007199254740991.0,
                        )
                })
            {
                return Err(Error::new(
                    400,
                    "Invalid management sessions; no session was restored.",
                ));
            }
            self.saved = Some(saved);
        }
        Ok(self.saved.as_ref().unwrap())
    }
    pub fn matching(
        &mut self,
        store: &Store,
        binding: &str,
        cookie: &str,
    ) -> Result<Option<(String, f64)>> {
        let Some(proof) = proof(cookie) else {
            return Ok(None);
        };
        let hash = digest(proof);
        let binding = digest(binding);
        let saved = self.load(store)?;
        for id in value::array(saved, value::prop(saved, "sessions")).unwrap() {
            let expires = value::number(saved, value::get(saved, id, "expiresAt")).unwrap();
            if value::string(saved, value::get(saved, id, "proofHash")).as_deref() == Some(&hash)
                && value::string(saved, value::get(saved, id, "bindingHash")).as_deref()
                    == Some(&binding)
                && expires > now()
            {
                return Ok(Some((proof.to_owned(), expires)));
            }
        }
        Ok(None)
    }
    fn cookie(proof: &str, expires: f64) -> String {
        format!(
            "c2l_management={proof}; HttpOnly; SameSite=Strict; Path=/api; Max-Age={}",
            ((expires - now()) / 1000.0).floor().max(0.0) as u64
        )
    }
    pub fn establish(
        &mut self,
        store: &Store,
        binding: &str,
        cookies: &str,
        launcher: bool,
    ) -> Result<(f64, String)> {
        if let Some((proof, expires)) = self.matching(store, binding, cookies)? {
            return Ok((expires, Self::cookie(&proof, expires)));
        }
        if !launcher {
            return Err(Error::new(
                401,
                "Open the installed Chat2Local launcher to verify this browser.",
            ));
        }
        let binding_hash = digest(binding);
        let saved = self.load(store)?;
        let mut next = saved.try_clone()?;
        let sessions = value::array(&next, value::prop(&next, "sessions"))
            .unwrap()
            .into_iter()
            .filter(|id| {
                value::number(&next, value::get(&next, *id, "expiresAt")).unwrap() > now()
                    && value::string(&next, value::get(&next, *id, "bindingHash")).as_deref()
                        == Some(&binding_hash)
            })
            .collect::<Vec<_>>();
        if sessions.len() >= 16 {
            return Err(Error::new(429, "Too many verified management browsers."));
        }
        let proof = random(32)?;
        let expires = now() + 7.0 * 86400000.0;
        value::put(&mut next, "sessions", Value::Array(sessions))?;
        let record=value::parse(serde_json::json!({"proofHash":digest(&proof),"bindingHash":binding_hash,"expiresAt":expires}).to_string().as_bytes())?;
        let record = next.import(record, usize::MAX)?;
        next.push(value::prop(&next, "sessions").unwrap(), record)?;
        store.save_private_record("management-sessions", &next)?;
        self.saved = Some(next);
        Ok((expires, Self::cookie(&proof, expires)))
    }
    pub fn logout(&mut self, store: &Store, cookies: &str) -> Result<String> {
        let hash = proof(cookies).map(digest);
        let mut next = self.load(store)?.try_clone()?;
        let sessions = value::array(&next, value::prop(&next, "sessions"))
            .unwrap()
            .into_iter()
            .filter(|id| {
                value::number(&next, value::get(&next, *id, "expiresAt")).unwrap() > now()
                    && hash.as_ref().is_none_or(|h| {
                        value::string(&next, value::get(&next, *id, "proofHash")).as_deref()
                            != Some(h)
                    })
            })
            .collect();
        value::put(&mut next, "sessions", Value::Array(sessions))?;
        store.save_private_record("management-sessions", &next)?;
        self.saved = Some(next);
        Ok("c2l_management=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0".into())
    }
}
