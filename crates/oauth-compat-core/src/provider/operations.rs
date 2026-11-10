mod client;
mod grant;
mod token;
use super::{Error, Result, runtime::C, value::J};
use crate::value::{base64, encode_base64};
use chat2local_js_value_compat::Value;
use serde_json::json;
const SCOPES: [&str; 5] = [
    "files:read",
    "files:propose",
    "files:write",
    "terminal:execute",
    "offline_access",
];

pub(super) async fn run(c: C, op: String, a: J) -> Result<J> {
    match op.as_str() {
        "cors" => cors(&c, &a),
        "lookupClient" => lookup(&c, a.get("clientId")?).await,
        "parseAuthRequest" => client::parse(&c, &a).await,
        "completeAuthorization" => grant::complete(&c, &a).await,
        "listUserGrants" => grant::list(&c, a.get("userId")?, a.get("options")?).await,
        "revokeGrant" => grant::revoke(&c, a.get("grantId")?, a.get("userId")?).await,
        "fetch" => fetch(&c, &a).await,
        _ => Err(Error::Core),
    }
}
async fn fetch(c: &C, a: &J) -> Result<J> {
    let url = url(c, &a.get("url")?).await?;
    let path = url.get("pathname")?.text()?;
    let api = path.starts_with("/mcp");
    let metadata = path == "/.well-known/oauth-authorization-server";
    let protected = path == "/.well-known/oauth-protected-resource"
        || path.starts_with("/.well-known/oauth-protected-resource/");
    let token = path == "/oauth/token";
    let register = path == "/oauth/register";
    if a.get("method")?.is("OPTIONS") && (api || metadata || protected || token || register) {
        return response(
            c,
            204,
            c.arena.null(),
            c.arena.obj(vec![("Content-Length", c.arena.s("0"))]),
            true,
        );
    }
    if metadata || protected {
        let origin = url.get("origin")?;
        let o = origin.text()?;
        let metadata = if protected {
            c.arena.obj(vec![
                ("resource", resource(c, a)?),
                ("authorization_servers", c.arena.arr(vec![origin])),
                ("scopes_supported", strings(c, &SCOPES[..4])),
                ("bearer_methods_supported", strings(c, &["header"])),
                ("resource_name", c.arena.s("Chat2Local")),
            ])
        } else {
            c.arena.obj(vec![
                ("issuer", origin),
                (
                    "authorization_endpoint",
                    c.arena.s(format!("{o}/authorize")),
                ),
                ("token_endpoint", c.arena.s(format!("{o}/oauth/token"))),
                (
                    "registration_endpoint",
                    c.arena.s(format!("{o}/oauth/register")),
                ),
                ("scopes_supported", strings(c, &SCOPES)),
                ("response_types_supported", strings(c, &["code"])),
                ("response_modes_supported", strings(c, &["query"])),
                (
                    "grant_types_supported",
                    strings(c, &["authorization_code", "refresh_token"]),
                ),
                (
                    "token_endpoint_auth_methods_supported",
                    strings(c, &["client_secret_basic", "client_secret_post", "none"]),
                ),
                ("revocation_endpoint", c.arena.s(format!("{o}/oauth/token"))),
                ("code_challenge_methods_supported", strings(c, &["S256"])),
                (
                    "authorization_response_iss_parameter_supported",
                    c.arena.bool(true),
                ),
                ("client_id_metadata_document_supported", c.arena.bool(false)),
            ])
        };
        return json_response(c, 200, metadata, false);
    }
    if token || register {
        let result = if token {
            token::endpoint(c, a).await
        } else {
            client::register(c, a).await
        };
        return match result {
            Err(Error::OAuth {
                code,
                description,
                status,
                headers,
            }) => {
                let h = c.arena.parse(&headers.to_string())?;
                let out = json_response(
                    c,
                    status,
                    c.arena.obj(vec![
                        ("error", c.arena.s(code)),
                        ("error_description", c.arena.units(description)),
                    ]),
                    true,
                )?;
                let target = out.get("headers")?;
                for (k, v) in h.entries() {
                    target.set(&String::from_utf16_lossy(&k), &v)?;
                }
                Ok(out)
            }
            v => v,
        };
    }
    Ok(c.arena.obj(vec![
        ("kind", c.arena.s(if api { "api" } else { "default" })),
        ("cors", c.arena.bool(api)),
        ("resource", resource(c, a)?),
        ("scopes", strings(c, &SCOPES)),
    ]))
}
fn cors(c: &C, a: &J) -> Result<J> {
    let headers = a.get("headers")?.array()?;
    let get = |name: &str| -> Result<Option<J>> {
        for p in &headers {
            let p = p.array()?;
            if p[0].text()?.eq_ignore_ascii_case(name) {
                return Ok(Some(p[1].clone()));
            }
        }
        Ok(None)
    };
    let mut patch = vec![
        c.arena.arr(vec![
            c.arena.s("Access-Control-Allow-Origin"),
            a.get("origin")?,
        ]),
        c.arena.arr(vec![
            c.arena.s("Access-Control-Allow-Methods"),
            c.arena.s("*"),
        ]),
        c.arena.arr(vec![
            c.arena.s("Access-Control-Allow-Headers"),
            c.arena.s("Authorization, *"),
        ]),
    ];
    let mut exposed = get("Access-Control-Expose-Headers")?
        .map(|s| s.text())
        .transpose()?
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for name in ["WWW-Authenticate", "Retry-After"] {
        if !exposed.iter().any(|s| s.eq_ignore_ascii_case(name)) {
            exposed.push(name.into());
        }
    }
    if !exposed.is_empty() {
        patch.push(c.arena.arr(vec![
            c.arena.s("Access-Control-Expose-Headers"),
            c.arena.s(exposed.join(", ")),
        ]));
    }
    patch.push(c.arena.arr(vec![
        c.arena.s("Access-Control-Max-Age"),
        c.arena.s("86400"),
    ]));
    Ok(c.arena.arr(patch))
}
fn strings(c: &C, items: &[&str]) -> J {
    c.arena.arr(items.iter().map(|s| c.arena.s(s)).collect())
}
fn resource(c: &C, a: &J) -> Result<J> {
    Ok(c.arena.s(format!("{}/mcp", a.get("origin")?.text()?)))
}
fn response(c: &C, status: u16, body: J, headers: J, cors: bool) -> Result<J> {
    Ok(c.arena.obj(vec![
        ("kind", c.arena.s("response")),
        ("status", c.arena.num(status.into())),
        ("body", body),
        ("headers", headers),
        ("cors", c.arena.bool(cors)),
    ]))
}
fn json_response(c: &C, status: u16, body: J, no_cache: bool) -> Result<J> {
    let headers = c
        .arena
        .obj(vec![("Content-Type", c.arena.s("application/json"))]);
    if no_cache {
        headers.set("Cache-Control", &c.arena.s("no-store"))?;
        headers.set("Pragma", &c.arena.s("no-cache"))?;
    }
    response(
        c,
        status,
        c.arena.s(body.json()?.ok_or(Error::Core)?),
        headers,
        true,
    )
}
fn error_status(code: &str, message: &str, status: u16) -> Error {
    Error::OAuth {
        code: code.into(),
        description: message.encode_utf16().collect(),
        status,
        headers: json!({}),
    }
}
async fn url(c: &C, v: &J) -> Result<J> {
    c.effect("url", json!({"input":v.wire()?})).await
}
async fn kv_get(c: &C, key: J) -> Result<J> {
    let t = c.effect("kv_get", json!({"key":key.wire()?})).await?;
    if t.nullish() {
        Ok(c.arena.null())
    } else {
        c.arena.parse_units(&t.str()?)
    }
}
async fn kv_put(c: &C, key: J, value: &J, options: &J) -> Result<()> {
    c.effect("kv_put",json!({"key":key.wire()?,"text":value.json()?.ok_or(Error::Core)?,"options":options.wire()?})).await?;
    Ok(())
}
async fn kv_delete(c: &C, key: J) -> Result<J> {
    c.effect("kv_delete", json!({"key":key.wire()?})).await
}

fn storage_key(c: &C, prefix: &str, parts: &[&J]) -> Result<J> {
    let mut units = prefix.encode_utf16().collect::<Vec<_>>();
    for p in parts {
        units.push(58);
        units.extend(p.string()?);
    }
    Ok(c.arena.units(units))
}
async fn clock(c: &C) -> Result<f64> {
    Ok((c.effect("clock", json!({})).await?.number()? / 1000.0).floor())
}
async fn random(c: &C, len: usize) -> Result<J> {
    let bytes = c.effect("random", json!({"length":len})).await?.array()?;
    if bytes.len() != len {
        return Err(Error::Core);
    }
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut units = vec![];
    for b in bytes {
        let n = b.number()?;
        if !(0.0..=255.0).contains(&n) || n.fract() != 0.0 {
            return Err(Error::Core);
        }
        units.push(u16::from(alphabet[n as usize % 64]));
    }
    Ok(c.arena.units(units))
}
async fn digest(c: &C, v: &J) -> Result<Vec<u8>> {
    let raw = c
        .effect(
            "digest",
            json!({"algorithm":"SHA-256","bytes":encode_base64(v.text()?.as_bytes())}),
        )
        .await?;
    base64(&raw.string()?).map_err(|_| Error::Core)
}
async fn hash(c: &C, v: &J) -> Result<J> {
    Ok(c.arena.s(digest(c, v)
        .await?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()))
}
// Effect IDs are integer handles. Keep their JSON representation stable across
// the JavaScript round trip used by exact effect confirmation.
fn key_handle(value: &J) -> Result<u32> {
    match value.val() {
        Value::Number(n) if (1.0..=u32::MAX as f64).contains(&n) && n.fract() == 0.0 => {
            Ok(n as u32)
        }
        _ => Err(Error::Core),
    }
}
async fn wrapping(c: &C, token: &J) -> Result<J> {
    const KEY: [u8; 32] = [
        34, 126, 38, 134, 141, 241, 225, 109, 128, 112, 234, 23, 151, 91, 71, 166, 130, 24, 250,
        135, 40, 174, 222, 133, 181, 29, 74, 217, 150, 202, 202, 67,
    ];
    let key=c.effect("import_key",json!({"format":"raw","bytes":encode_base64(&KEY),"algorithm":{"name":"HMAC","hash":"SHA-256"},"extractable":false,"usages":["sign"]})).await?;
    let bytes=c.effect("sign",json!({"algorithm":"HMAC","key":key_handle(&key)?,"bytes":encode_base64(token.text()?.as_bytes())})).await?;
    c.effect("import_key",json!({"format":"raw","bytes":bytes.text()?,"algorithm":{"name":"AES-KW"},"extractable":false,"usages":["wrapKey","unwrapKey"]})).await
}
async fn wrap(c: &C, token: &J, key: &J) -> Result<J> {
    let w = wrapping(c, token).await?;
    c.effect("wrap_key",json!({"format":"raw","key":key_handle(key)?,"wrappingKey":key_handle(&w)?,"algorithm":{"name":"AES-KW"}})).await
}
async fn unwrap(c: &C, token: &J, encoded: &J) -> Result<J> {
    let w = wrapping(c, token).await?;
    let bytes = base64(&encoded.string()?)
        .map_err(|_| Error::normal("InvalidCharacterError", "Invalid character"))?;
    c.effect("unwrap_key",json!({"format":"raw","bytes":encode_base64(&bytes),"key":key_handle(&w)?,"algorithm":{"name":"AES-KW"},"unwrappedAlgorithm":{"name":"AES-GCM"},"extractable":true,"usages":["encrypt","decrypt"]})).await
}
async fn encrypt(c: &C, props: &J) -> Result<(J, J)> {
    let key=c.effect("generate_key",json!({"algorithm":{"name":"AES-GCM","length":256},"extractable":true,"usages":["encrypt","decrypt"]})).await?;
    let text = props.json()?.unwrap_or_default();
    let bytes=c.effect("encrypt",json!({"algorithm":{"name":"AES-GCM","iv":[0,0,0,0,0,0,0,0,0,0,0,0]},"key":key_handle(&key)?,"bytes":encode_base64(text.as_bytes())})).await?;
    Ok((bytes, key))
}
async fn decrypt(c: &C, key: &J, cipher: &J) -> Result<J> {
    let bytes = base64(&cipher.string()?)
        .map_err(|_| Error::normal("InvalidCharacterError", "Invalid character"))?;
    let raw=c.effect("decrypt",json!({"algorithm":{"name":"AES-GCM","iv":[0,0,0,0,0,0,0,0,0,0,0,0]},"key":key_handle(key)?,"bytes":encode_base64(&bytes)})).await?;
    let bytes = base64(&raw.string()?).map_err(|_| Error::Core)?;
    let text = String::from_utf8_lossy(&bytes);
    c.arena
        .parse(text.strip_prefix('\u{feff}').unwrap_or(&text))
}
async fn lookup(c: &C, id: J) -> Result<J> {
    let client = kv_get(c, storage_key(c, "client", &[&id])?).await?;
    if !client.truth() {
        return Ok(c.arena.null());
    }
    let public = client.spread()?;
    public.remove("authMethodExplicit")?;
    Ok(public)
}
fn split(c: &C, s: &J, separator: u16, filter_empty: bool) -> Result<J> {
    Ok(c.arena.arr(
        s.str()?
            .split(|v| *v == separator)
            .filter(|s| !filter_empty || !s.is_empty())
            .map(|s| c.arena.units(s.to_vec()))
            .collect(),
    ))
}
fn join(c: &C, items: &J, separator: &str) -> Result<J> {
    let mut units = vec![];
    for (i, item) in items.array()?.iter().enumerate() {
        if i > 0 {
            units.extend(separator.encode_utf16());
        }
        if !item.nullish() {
            units.extend(item.string()?);
        }
    }
    Ok(c.arena.units(units))
}
fn includes(list: &J, item: &J) -> Result<bool> {
    match list.val() {
        Value::Array(_) | Value::SparseArray { .. } => Ok(list.array()?.iter().any(|i| i.eq(item))),
        Value::String(s) => {
            let needle = item.string()?;
            Ok(needle.is_empty() || s.windows(needle.len()).any(|w| w == needle))
        }
        _ => Err(Error::normal("TypeError", "includes is not a function")),
    }
}
fn downscope(c: &C, requested: &J, allowed: &J) -> Result<J> {
    if !requested.truth() {
        return Ok(allowed.clone());
    }
    let requested = match requested.val() {
        Value::String(_) => split(c, requested, 32, true)?,
        _ => requested.clone(),
    };
    Ok(c.arena.arr(
        requested
            .present_array()?
            .into_iter()
            .filter_map(|s| match includes(allowed, &s) {
                Ok(true) => Some(Ok(s)),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<Vec<_>>>()?,
    ))
}
fn projection(c: &C, props: &J, scopes: &J) -> Result<J> {
    let out = props.spread()?;
    out.set(
        "scopes",
        &c.arena.arr(
            scopes
                .present_array()?
                .into_iter()
                .filter(|s| SCOPES[..4].iter().any(|v| s.is(v)))
                .collect(),
        ),
    )?;
    Ok(out)
}
async fn valid_resource(c: &C, v: &J) -> Result<bool> {
    if !v.truth() {
        return Ok(false);
    }
    let items = if matches!(v.val(), Value::Array(_) | Value::SparseArray { .. }) {
        v.array()?
    } else {
        vec![v.clone()]
    };
    if items.is_empty() {
        return Ok(false);
    }
    for item in items {
        if !matches!(item.val(), Value::String(_)) || !item.truth() {
            return Ok(false);
        }
        let u = url(c, &item).await?;
        if u.nullish()
            || !u.get("hash")?.is("")
            || !(u.get("protocol")?.is("http:") || u.get("protocol")?.is("https:"))
        {
            return Ok(false);
        }
    }
    Ok(true)
}
fn exact(v: &J, target: &J) -> bool {
    v.eq(target) || v.array().is_ok_and(|a| a.len() == 1 && a[0].eq(target))
}
async fn audience(c: &C, a: &J, requested: &J, stored: &J) -> Result<J> {
    if !requested.undefined() && !valid_resource(c, requested).await? {
        return Err(Error::oauth(
            "invalid_target",
            "The resource parameter must be a valid absolute URI without a fragment",
        ));
    }
    if !stored.undefined() && !valid_resource(c, stored).await? {
        return Err(Error::oauth(
            "invalid_target",
            "The authorization grant contains an invalid resource",
        ));
    }
    let target = resource(c, a)?;
    if !requested.undefined() && !exact(requested, &target) {
        return Err(Error::oauth(
            "invalid_target",
            format!(
                "The resource parameter must exactly match {}",
                target.text()?
            ),
        ));
    }
    if stored.undefined() || exact(stored, &target) {
        Ok(target)
    } else {
        Err(Error::oauth(
            "invalid_target",
            "The authorization grant is not bound to the configured resource",
        ))
    }
}
fn pkce_method(method: &J, validate: bool) -> Result<J> {
    let method = if method.nullish() {
        method.arena.s("plain")
    } else {
        method.clone()
    };
    if !(method.is("plain") || method.is("S256")) {
        return Err(Error::auth(
            "invalid_request",
            message("Unsupported PKCE code_challenge_method: ", &method, "")?,
        ));
    }
    if validate && method.is("plain") {
        return Err(Error::auth(
            "invalid_request",
            "The plain PKCE method is not allowed. Use S256 instead.",
        ));
    }
    Ok(method)
}
fn validate_auth(request: &J, client: &J) -> Result<()> {
    let response = request.get("responseType")?;
    if !response.truth() {
        return Err(Error::auth("invalid_request", "response_type is required"));
    }
    if !response.is("code") {
        return Err(Error::auth(
            "unsupported_response_type",
            message(
                "The authorization server does not support response_type ",
                &response,
                "",
            )?,
        ));
    }
    let registered = client.get("responseTypes")?;
    if !registered.nullish() && !includes(&registered, &response)? {
        return Err(Error::auth(
            "unauthorized_client",
            message(
                "The client is not registered for response_type ",
                &response,
                "",
            )?,
        ));
    }
    validate_pkce(request, client)
}
fn validate_pkce(request: &J, client: &J) -> Result<()> {
    if request.get("codeChallenge")?.truth() {
        pkce_method(&request.get("codeChallengeMethod")?, true)?;
    } else if request.get("codeChallengeMethod")?.truth() {
        return Err(Error::auth(
            "invalid_request",
            "PKCE code_challenge is required when code_challenge_method is provided.",
        ));
    } else if request.get("responseType")?.is("code")
        && client.get("tokenEndpointAuthMethod")?.is("none")
    {
        return Err(Error::auth(
            "invalid_request",
            "Public clients must use PKCE with the authorization code flow.",
        ));
    }
    Ok(())
}
fn redirect_scheme(v: &J) -> Result<()> {
    let s = String::from_utf16_lossy(&v.str()?);
    let s = s.trim_matches(|c: char| js_whitespace(c));
    if s.chars().any(|c| matches!(u32::from(c),0..=31|127..=159)) {
        return Err(Error::normal("Error", "Invalid redirect URI"));
    }
    let end = s
        .find(':')
        .ok_or_else(|| Error::normal("Error", "Invalid redirect URI"))?;
    if [
        "javascript:",
        "data:",
        "vbscript:",
        "file:",
        "mailto:",
        "blob:",
    ]
    .contains(&s[..=end].to_lowercase().as_str())
    {
        return Err(Error::normal("Error", "Invalid redirect URI"));
    }
    Ok(())
}
fn loopback(u: &J) -> Result<bool> {
    if u.nullish() {
        return Ok(false);
    }
    let host = u.get("hostname")?.text()?;
    Ok(host == "[::1]"
        || host == "::1"
        || host.eq_ignore_ascii_case("localhost")
        || host
            .split('.')
            .collect::<Vec<_>>()
            .as_slice()
            .split_first()
            .is_some_and(|(first, rest)| {
                *first == "127"
                    && rest.len() == 3
                    && rest.iter().all(|v| {
                        !v.is_empty() && v.len() <= 3 && v.bytes().all(|b| b.is_ascii_digit())
                    })
            }))
}
async fn redirect(c: &C, request: &J, registered: &J) -> Result<bool> {
    for reg in registered.array()? {
        let req_url = url(c, request).await?;
        let reg_url = url(c, &reg).await?;
        if loopback(&req_url)? && loopback(&reg_url)? {
            if ["protocol", "hostname", "pathname", "search"]
                .iter()
                .all(|k| {
                    req_url
                        .get(k)
                        .and_then(|a| reg_url.get(k).map(|b| a.eq(&b)))
                        .unwrap_or(false)
                })
            {
                return Ok(true);
            }
        } else if request.eq(&reg) {
            return Ok(true);
        }
    }
    Ok(false)
}
fn storage_error(e: Error) -> Error {
    match &e {
        Error::Host { name, message, .. }
            if name != "NonError"
                && String::from_utf16_lossy(message)
                    .to_lowercase()
                    .contains("429 too many requests") =>
        {
            Error::OAuth {
                code: "temporarily_unavailable".into(),
                description: "Token issuance is temporarily unavailable; retry shortly"
                    .encode_utf16()
                    .collect(),
                status: 429,
                headers: json!({"Retry-After":"30"}),
            }
        }
        _ => e,
    }
}
async fn save_grant(c: &C, key: J, grant: &J, now: f64) -> Result<()> {
    let options = c.arena.obj(vec![]);
    let expires = grant.get("expiresAt")?;
    if !expires.undefined() {
        let n = expires.number()?;
        options.set(
            "expiration",
            &c.arena.num(if n.is_nan() { n } else { n.max(now + 65.0) }),
        )?;
    }
    kv_put(c, key, grant, &options).await.map_err(storage_error)
}

fn message(prefix: &str, value: &J, suffix: &str) -> Result<Vec<u16>> {
    let mut units = prefix.encode_utf16().collect::<Vec<_>>();
    units.extend(value.string()?);
    units.extend(suffix.encode_utf16());
    Ok(units)
}
fn js_whitespace(c: char) -> bool {
    matches!(c, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}
