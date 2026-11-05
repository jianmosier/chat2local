use crate::value::*;
use chat2local_js_value_compat::{Document, Value, ValueId};
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use serde::Deserialize;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    token: Scalar,
    jwks: Vec<u16>,
    issuer: Scalar,
    client_id: Scalar,
    nonce: Scalar,
    now: Scalar,
    now_graph: Option<Vec<NumericNode>>,
    access: Scalar,
}
pub struct Prepared {
    packet: Packet,
    header: Document,
    claims: Document,
    raw: Document,
    token_issuer: Scalar,
    parts: Vec<String>,
    skew: f64,
    business_now: f64,
}
fn jwt(part: &str) -> Result<Document> {
    let units: Vec<u16> = part.encode_utf16().collect();
    if units.is_empty() || units.len() > 32768 {
        return Err(error("Malformed identity token."));
    }
    let bytes = base64(&units, 0).ok_or_else(|| error("Malformed identity token."))?;
    let s = std::str::from_utf8(&bytes).map_err(|_| error("Malformed identity token."))?;
    parse(
        &s.strip_prefix('\u{feff}')
            .unwrap_or(s)
            .encode_utf16()
            .collect::<Vec<_>>(),
    )
    .map_err(|e| {
        if e["kind"] == "unavailable" {
            e
        } else {
            error("Malformed identity token.")
        }
    })
}
fn included(d: &Document, id: ValueId, text: &str) -> bool {
    array(d, id).is_some_and(|a| a.iter().any(|v| is(d, *v, text)))
}
pub fn pre(packet: Packet) -> Result<Prepared> {
    let t = packet
        .token
        .string()
        .filter(|s| s.len() <= 32768)
        .ok_or_else(|| error("Invalid identity token."))?;
    let token = String::from_utf16_lossy(t);
    let parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    if parts.len() != 3 {
        return Err(error("Invalid identity token."));
    }
    let header = jwt(&parts[0])?;
    let claims = jwt(&parts[1])?;
    let h = header.root();
    if !truth(&header, Some(h))
        || !field_is(&header, h, "alg", "RS256")
        || prop(&header, h, "kid")
            .and_then(|id| string(&header, id))
            .is_none_or(|s| s.len() > 256)
        || ["jku", "jwk", "x5u", "crit", "b64"]
            .iter()
            .any(|k| prop(&header, h, k).is_some())
    {
        return Err(error("Unsupported identity signature."));
    }
    let raw = parse(&packet.jwks)?;
    let keys = prop(&raw, raw.root(), "keys")
        .and_then(|id| array(&raw, id))
        .filter(|a| a.len() <= 32)
        .ok_or_else(|| error("Invalid identity key set."))?;
    let kid = string(&header, prop(&header, h, "kid").unwrap()).unwrap();
    let mut candidates = Vec::new();
    for key in keys {
        if matches!(val(&raw, *key), Value::Null) {
            return Err(native("kid"));
        }
        let candidate = prop(&raw, *key, "kid").and_then(|id| string(&raw, id)) == Some(kid)
            && field_is(&raw, *key, "kty", "RSA")
            && (!truth(&raw, prop(&raw, *key, "alg")) || field_is(&raw, *key, "alg", "RS256"))
            && (!truth(&raw, prop(&raw, *key, "use")) || field_is(&raw, *key, "use", "sig"))
            && (!truth(&raw, prop(&raw, *key, "key_ops"))
                || prop(&raw, *key, "key_ops").is_some_and(|id| included(&raw, id, "verify")))
            && !truth(&raw, prop(&raw, *key, "d"));
        if candidate {
            candidates.push(*key);
        }
    }
    if candidates.len() != 1 {
        return Err(error("Unknown or invalid identity signing key."));
    }
    let n = prop(&raw, candidates[0], "n")
        .and_then(|id| string(&raw, id))
        .filter(|s| !s.is_empty() && s.len() <= 32768)
        .ok_or_else(|| error("Malformed identity token."))?;
    let bytes = base64(n, 0).ok_or_else(|| error("Malformed identity token."))?;
    if bytes.len() < 256 {
        return Err(error("Unknown or invalid identity signing key."));
    }
    if matches!(val(&claims, claims.root()), Value::Null) {
        return Err(native("iss"));
    }
    let token_issuer = if packet.issuer.string().is_some_and(|s| {
        s.iter()
            .copied()
            .eq("https://accounts.google.com".encode_utf16())
    }) && field_is(&claims, claims.root(), "iss", "accounts.google.com")
    {
        Scalar::String {
            units: "accounts.google.com".encode_utf16().collect(),
        }
    } else {
        packet.issuer.clone()
    };
    Ok(Prepared {
        packet,
        header,
        claims,
        raw,
        token_issuer,
        parts,
        skew: 0.0,
        business_now: f64::NAN,
    })
}

impl Prepared {
    pub fn skew(&mut self, wall: f64) -> Result<()> {
        self.business_now = if let Some(nodes) = &self.packet.now_graph {
            numeric_graph(nodes)?
        } else {
            self.packet.now.numeric()
        };
        let skew = ((self.business_now - wall) / 1000.0).floor();
        self.skew = if skew.is_finite() { skew } else { 0.0 };
        if !self.token_issuer.string_type()
            || self.token_issuer.length() == 0
            || !self.packet.client_id.string_type()
            || self.packet.client_id.length() == 0
            || (!matches!(self.packet.nonce, Scalar::Undefined)
                && (!self.packet.nonce.string_type() || self.packet.nonce.length() == 0))
            || (self.packet.access.truth() && !self.packet.access.string_type())
            || !object(&self.header, self.header.root())
            || !object(&self.claims, self.claims.root())
        {
            return Err(generic());
        }
        Ok(())
    }
    pub fn finish(self, wall: f64) -> Result<Json> {
        let d = &self.claims;
        let c = d.root();
        let f = |k: &str| prop(d, c, k);
        let numeric = |k: &str| f(k).and_then(|id| num(d, id));
        let sdk_now = (wall / 1000.0).floor() + self.skew;
        for key in ["exp", "iat", "nbf"] {
            if f(key).is_some() && numeric(key).is_none() {
                return Err(generic());
            }
        }
        if numeric("exp").is_some_and(|n| n <= sdk_now)
            || numeric("nbf").is_some_and(|n| n > sdk_now)
        {
            return Err(generic());
        }
        if f("iss").is_some_and(|id| string(d, id).is_none())
            || f("aud").is_some_and(|id| string(d, id).is_none() && array(d, id).is_none())
        {
            return Err(generic());
        }
        let required = if matches!(self.packet.nonce, Scalar::Undefined) {
            vec!["aud", "exp", "iat", "iss", "sub"]
        } else {
            vec!["aud", "exp", "iat", "iss", "sub", "nonce"]
        };
        if required.iter().any(|k| f(k).is_none()) {
            return Err(generic());
        }
        if !f("iss").is_some_and(|id| same(d, id, &self.token_issuer)) {
            return Err(generic());
        }
        let aud = f("aud").unwrap();
        let audiences = if let Some(a) = array(d, aud) {
            a.to_vec()
        } else {
            vec![aud]
        };
        if !audiences
            .iter()
            .any(|id| same(d, *id, &self.packet.client_id))
            || f("sub").and_then(|id| string(d, id)).is_none()
        {
            return Err(generic());
        }
        if array(d, aud).is_some_and(|a| a.len() != 1)
            && !f("azp").is_some_and(|id| same(d, id, &self.packet.client_id))
        {
            return Err(generic());
        }
        if f("auth_time").is_some()
            && numeric("auth_time").is_none_or(|n| !n.is_finite() || n < 0.0)
        {
            return Err(generic());
        }
        if match &self.packet.nonce {
            Scalar::Undefined => f("nonce").is_some(),
            n => !f("nonce").is_some_and(|id| same(d, id, n)),
        } {
            return Err(generic());
        }
        self.signature()?;
        if audiences.len() != 1
            || !same(d, audiences[0], &self.packet.client_id)
            || f("azp").is_some_and(|id| !same(d, id, &self.packet.client_id))
        {
            return Err(error("Identity issuer or audience mismatch."));
        }
        let safe = |n: f64| n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0;
        let seconds = (self.business_now / 1000.0).floor();
        let exp = numeric("exp").unwrap();
        let iat = numeric("iat").unwrap();
        if !safe(exp)
            || exp <= seconds
            || !safe(iat)
            || iat > seconds + 30.0
            || iat < seconds - 600.0
            || exp <= iat
            || numeric("nbf").is_some_and(|n| !safe(n) || n > seconds + 30.0)
        {
            return Err(error(
                "Identity token is expired or outside this login window.",
            ));
        }
        let nonce_ok = self
            .packet
            .nonce
            .string()
            .is_some_and(|s| s.len() == 64 && s.iter().all(|c| matches!(c,48..=57|97..=102)));
        let sub = f("sub").and_then(|id| string(d, id)).unwrap();
        if !nonce_ok
            || sub.is_empty()
            || sub.len() > 255
            || !sub.iter().all(|c| matches!(c, 33..=126))
        {
            return Err(error("Identity nonce or subject mismatch."));
        }
        if let Some(hash) = f("at_hash") {
            if !self.packet.access.string_type() || self.packet.access.length() > 16384 {
                return Err(error("Invalid identity access-token binding."));
            }
            let access = self.packet.access.string().ok_or_else(unavailable)?;
            let digest = Sha256::digest(String::from_utf16_lossy(access).as_bytes());
            if string(d, hash) != Some(b64(&digest[..16]).as_slice()) {
                return Err(error("Identity access-token binding mismatch."));
            }
        }
        let name = if let Some(name) = f("name").and_then(|id| string(d, id)) {
            name.iter()
                .copied()
                .filter(|c| !matches!(c, 0..=31 | 127))
                .take(120)
                .collect::<Vec<_>>()
        } else {
            "已登录账号".encode_utf16().collect()
        };
        Ok(
            json!({"kind":"identity","issuer":self.packet.issuer.string().ok_or_else(unavailable)?,"subject":sub,"displayName":name}),
        )
    }
    fn signature(&self) -> Result<()> {
        let normalized = self
            .raw
            .stringify(LIMITS)
            .map_err(|_| unavailable())?
            .ok_or_else(generic)?;
        let doc = Document::parse_str(&normalized, LIMITS).map_err(|_| unavailable())?;
        let keys = prop(&doc, doc.root(), "keys")
            .and_then(|id| array(&doc, id))
            .ok_or_else(generic)?;
        if keys.iter().any(|id| !object(&doc, *id)) {
            return Err(generic());
        }
        let kid = string(
            &self.header,
            prop(&self.header, self.header.root(), "kid").unwrap(),
        )
        .unwrap();
        let mut candidates = Vec::new();
        for key in keys {
            if !field_is(&doc, *key, "kty", "RSA")
                || prop(&doc, *key, "kid").and_then(|id| string(&doc, id)) != Some(kid)
                || prop(&doc, *key, "alg").is_some_and(|id| !is(&doc, id, "RS256"))
                || prop(&doc, *key, "use").is_some_and(|id| !is(&doc, id, "sig"))
            {
                continue;
            }
            if let Some(ops) = prop(&doc, *key, "key_ops") {
                match val(&doc, ops) {
                    Value::Null => (),
                    Value::Array(a) => {
                        if !a.iter().any(|id| is(&doc, *id, "verify")) {
                            continue;
                        }
                    }
                    Value::String(s) => {
                        if !String::from_utf16_lossy(s).contains("verify") {
                            continue;
                        }
                    }
                    _ => return Err(generic()),
                }
            }
            candidates.push(*key);
        }
        if candidates.len() != 1 {
            return Err(generic());
        }
        let key = candidates[0];
        for field in [
            "kty", "kid", "alg", "n", "e", "d", "crv", "x", "y", "k", "p", "q", "dp", "dq", "qi",
        ] {
            if let Some(id) = prop(&doc, key, field) {
                dom_string(&doc, id).ok_or_else(generic)?;
            }
        }
        if let Some(oth) = prop(&doc, key, "oth") {
            let values = array(&doc, oth).ok_or_else(generic)?;
            for id in values {
                if !matches!(
                    val(&doc, *id),
                    Value::Null | Value::Object(_) | Value::Array(_)
                ) {
                    return Err(generic());
                }
                for k in ["r", "d", "t"] {
                    if let Some(v) = prop(&doc, *id, k) {
                        dom_string(&doc, v).ok_or_else(generic)?;
                    }
                }
            }
        }
        if prop(&doc, key, "d").is_some() {
            return Err(generic());
        }
        let decode = |field: &str| -> Result<Vec<u8>> {
            let id = prop(&doc, key, field).ok_or_else(generic)?;
            base64(&dom_string(&doc, id).ok_or_else(generic)?, 1).ok_or_else(generic)
        };
        let mut n = decode("n")?;
        let mut e = decode("e")?;
        let nskip = n.iter().position(|b| *b != 0).unwrap_or(n.len());
        n.drain(..nskip);
        let eskip = e.iter().position(|b| *b != 0).unwrap_or(e.len());
        e.drain(..eskip);
        if n.len() < 256
            || n.len() > 2048
            || ![vec![3], vec![17], vec![37], vec![1, 0, 1]].contains(&e)
        {
            return Err(generic());
        }
        let key = RsaPublicKey::new_with_max_size(
            BigUint::from_bytes_be(&n),
            BigUint::from_bytes_be(&e),
            16384,
        )
        .map_err(|_| generic())?;
        let signature =
            base64(&self.parts[2].encode_utf16().collect::<Vec<_>>(), 1).ok_or_else(generic)?;
        let digest = Sha256::digest(format!("{}.{}", self.parts[0], self.parts[1]).as_bytes());
        key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
            .map_err(|_| generic())
    }
}
