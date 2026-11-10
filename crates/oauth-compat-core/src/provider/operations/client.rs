use super::*;

pub(super) async fn parse(c: &C, a: &J) -> Result<J> {
    let u = url(c, &a.get("url")?).await?;
    if u.nullish() {
        return Err(Error::normal("TypeError", "Invalid URL"));
    }
    let pairs = u.get("params")?.array()?;
    let get = |key: &str| -> Result<J> {
        for p in &pairs {
            let p = p.array()?;
            if p[0].is(key) {
                return Ok(p[1].clone());
            }
        }
        Ok(c.arena.s(""))
    };
    let request = c.arena.obj(vec![
        ("responseType", get("response_type")?),
        ("clientId", get("client_id")?),
        ("redirectUri", get("redirect_uri")?),
        ("scope", split(c, &get("scope")?, 32, true)?),
        ("state", get("state")?),
    ]);
    for (key, param) in [
        ("codeChallenge", "code_challenge"),
        ("codeChallengeMethod", "code_challenge_method"),
    ] {
        let v = get(param)?;
        request.set(key, &if v.truth() { v } else { c.arena.undef() })?;
    }
    let resources = pairs
        .iter()
        .filter_map(|p| {
            p.array()
                .ok()
                .filter(|p| p[0].is("resource"))
                .map(|p| p[1].clone())
        })
        .collect::<Vec<_>>();
    let given = match resources.len() {
        0 => c.arena.undef(),
        1 => resources[0].clone(),
        _ => c.arena.arr(resources),
    };
    let id = request.get("clientId")?;
    if !id.truth() {
        return Err(Error::auth("invalid_request", "client_id is required"));
    }
    let client = lookup(c, id).await?;
    if !client.truth() {
        return Err(Error::auth("invalid_request", "Invalid client_id"));
    }
    let redirect_uri = request.get("redirectUri")?;
    if redirect_scheme(&redirect_uri).is_err()
        || !redirect_uri.truth()
        || !redirect(c, &redirect_uri, &client.get("redirectUris")?).await?
    {
        return Err(Error::auth("invalid_request", "Invalid redirect URI"));
    }
    let issuer = u.get("origin")?;
    let safe = c.arena.obj(vec![
        ("redirectUri", redirect_uri),
        (
            "state",
            if request.get("state")?.truth() {
                request.get("state")?
            } else {
                c.arena.undef()
            },
        ),
        ("issuer", issuer.clone()),
    ]);
    let result = async {
        if !given.undefined() && !valid_resource(c, &given).await? {
            return Err(Error::auth(
                "invalid_target",
                "The resource parameter must be a valid absolute URI without a fragment",
            ));
        }
        let target = resource(c, a)?;
        if !given.undefined() && !exact(&given, &target) {
            return Err(Error::auth(
                "invalid_target",
                format!(
                    "The resource parameter must exactly match {}",
                    target.text()?
                ),
            ));
        }
        validate_auth(&request, &client)?;
        request.set("resource", &target)?;
        request.set("issuer", &issuer)?;
        Ok(request)
    }
    .await;
    result.map_err(|e| match e {
        Error::Authorization {
            code, description, ..
        } => Error::Authorization {
            code,
            description,
            redirect: safe.wire().ok(),
        },
        e => e,
    })
}
fn typeof_(v: &J) -> &'static str {
    match v.val() {
        Value::Undefined => "undefined",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        _ => "object",
    }
}
fn optional(v: J, name: &str, array: bool) -> Result<J> {
    if v.undefined() {
        return Ok(v);
    }
    if array {
        if !matches!(v.val(), Value::Array(_) | Value::SparseArray { .. }) {
            return Err(Error::normal(
                "Error",
                format!("Invalid {name}: expected array, got {}", typeof_(&v)),
            ));
        }
        if v.present_array()?
            .iter()
            .any(|v| !matches!(v.val(), Value::String(_)))
        {
            return Err(Error::normal(
                "Error",
                format!("Invalid {name}: array must contain only strings"),
            ));
        }
    } else if !matches!(v.val(), Value::String(_)) {
        return Err(Error::normal(
            "Error",
            format!("Invalid {name}: expected string, got {}", typeof_(&v)),
        ));
    }
    Ok(v)
}
fn named_error(name: &[u16], suffix: &str) -> Error {
    let mut message = "Invalid ".encode_utf16().collect::<Vec<_>>();
    message.extend(name);
    message.extend(suffix.encode_utf16());
    Error::normal("Error", message)
}
async fn localized(c: &C, v: J, name: &[u16], uri: bool) -> Result<J> {
    if v.undefined() {
        return Ok(v);
    }
    if !matches!(v.val(), Value::String(_)) {
        return Err(named_error(
            name,
            &format!(": expected string, got {}", typeof_(&v)),
        ));
    }
    if uri {
        let u = url(c, &v).await?;
        if u.nullish() || !(u.get("protocol")?.is("http:") || u.get("protocol")?.is("https:")) {
            return Err(named_error(
                name,
                ": must be an absolute http: or https: URL",
            ));
        }
    }
    Ok(v)
}
async fn http(c: &C, v: J, name: &str) -> Result<J> {
    let v = optional(v, name, false)?;
    if !v.undefined() {
        let u = url(c, &v).await?;
        if u.nullish() || !(u.get("protocol")?.is("http:") || u.get("protocol")?.is("https:")) {
            return Err(Error::normal(
                "Error",
                format!("Invalid {name}: must be an absolute http: or https: URL"),
            ));
        }
    }
    Ok(v)
}
fn consistency(preferred: &J, choices: &J, p: &str, q: &str) -> Result<()> {
    if !preferred.undefined() && !choices.undefined() && !includes(choices, preferred)? {
        return Err(Error::normal(
            "Error",
            format!("{p} must be included in {q}"),
        ));
    }
    Ok(())
}
async fn metadata(c: &C, raw: &J) -> Result<J> {
    if !matches!(raw.val(), Value::Object(_)) {
        return Err(Error::normal(
            "Error",
            "Client metadata must be a JSON object",
        ));
    }
    let preferred = optional(
        raw.get("token_endpoint_auth_method")?,
        "token_endpoint_auth_method",
        false,
    )?;
    let choices = optional(
        raw.get("token_endpoint_auth_methods_supported")?,
        "token_endpoint_auth_methods_supported",
        true,
    )?;
    let signing = optional(
        raw.get("token_endpoint_auth_signing_alg")?,
        "token_endpoint_auth_signing_alg",
        false,
    )?;
    let algs = optional(
        raw.get("token_endpoint_auth_signing_alg_values_supported")?,
        "token_endpoint_auth_signing_alg_values_supported",
        true,
    )?;
    consistency(
        &preferred,
        &choices,
        "token_endpoint_auth_method",
        "token_endpoint_auth_methods_supported",
    )?;
    consistency(
        &signing,
        &algs,
        "token_endpoint_auth_signing_alg",
        "token_endpoint_auth_signing_alg_values_supported",
    )?;
    optional(raw.get("client_id")?, "client_id", false)?;
    let uris = optional(raw.get("redirect_uris")?, "redirect_uris", true)?;
    let meta = c.arena.obj(vec![(
        "clientName",
        optional(raw.get("client_name")?, "client_name", false)?,
    )]);
    for (internal, external) in [
        ("clientUri", "client_uri"),
        ("logoUri", "logo_uri"),
        ("policyUri", "policy_uri"),
        ("tosUri", "tos_uri"),
        ("jwksUri", "jwks_uri"),
    ] {
        meta.set(internal, &http(c, raw.get(external)?, external).await?)?;
    }
    let i18n = c.arena.obj(vec![]);
    for (key, val) in raw.entries() {
        if let Some(index) = key.iter().position(|v| *v == 35) {
            let base = String::from_utf16_lossy(&key[..index]);
            if index + 1 < key.len()
                && [
                    "client_name",
                    "client_uri",
                    "logo_uri",
                    "tos_uri",
                    "policy_uri",
                ]
                .contains(&base.as_str())
            {
                let value = localized(c, val, &key, base != "client_name").await?;
                if !value.undefined() {
                    i18n.set_units(key, &value)?;
                }
            }
        }
    }
    meta.set(
        "i18n",
        &if i18n.entries().is_empty() {
            c.arena.undef()
        } else {
            i18n
        },
    )?;
    meta.set(
        "contacts",
        &optional(raw.get("contacts")?, "contacts", true)?,
    )?;
    let grants = optional(raw.get("grant_types")?, "grant_types", true)?;
    let grants = if grants.undefined() {
        strings(c, &["authorization_code"])
    } else {
        grants
    };
    let responses = optional(raw.get("response_types")?, "response_types", true)?;
    let responses = if responses.undefined() {
        strings(c, &["code"])
    } else {
        responses
    };
    let accepted = ["client_secret_basic", "client_secret_post", "none"];
    let advertised = if choices.undefined() {
        c.arena.arr(vec![if preferred.undefined() {
            c.arena.s("client_secret_basic")
        } else {
            preferred.clone()
        }])
    } else {
        choices.clone()
    };
    let method = if !preferred.undefined() && accepted.iter().any(|s| preferred.is(s)) {
        preferred.clone()
    } else if let Some(s) = accepted
        .iter()
        .find(|s| includes(&advertised, &c.arena.s(s)).unwrap_or(false))
    {
        c.arena.s(s)
    } else {
        let mut union = vec![];
        if !preferred.undefined() {
            union.push(preferred.clone())
        }
        for v in advertised.array()? {
            if !union.iter().any(|a| a.eq(&v)) {
                union.push(v)
            }
        }
        return Err(Error::normal(
            "Error",
            message(
                "Client does not support an accepted token endpoint authentication method. Supported methods: client_secret_basic, client_secret_post, none. Client advertised: ",
                &if union.is_empty() {
                    c.arena.s("(none)")
                } else {
                    join(c, &c.arena.arr(union), ", ")?
                },
                "",
            )?,
        ));
    };
    for grant in grants.array()? {
        if !["authorization_code", "refresh_token"]
            .iter()
            .any(|v| grant.is(v))
        {
            return Err(Error::normal(
                "Error",
                message("Unsupported grant_type: ", &grant, "")?,
            ));
        }
    }
    for response in responses.array()? {
        if !response.is("code") {
            return Err(Error::normal(
                "Error",
                message("Unsupported response_type: ", &response, "")?,
            ));
        }
    }
    if includes(&grants, &c.arena.s("authorization_code"))?
        != includes(&responses, &c.arena.s("code"))?
    {
        return Err(Error::normal(
            "Error",
            "grant_types authorization_code and response_types code must be registered together",
        ));
    }
    if uris.undefined() || uris.array()?.is_empty() {
        return Err(Error::normal(
            "Error",
            "redirect_uris is required and must not be empty",
        ));
    }
    for uri in uris.array()? {
        redirect_scheme(&uri)?;
    }
    meta.set("redirectUris", &uris)?;
    meta.set("grantTypes", &grants)?;
    meta.set("responseTypes", &responses)?;
    meta.set("tokenEndpointAuthMethod", &method)?;
    meta.set(
        "authMethodExplicit",
        &c.arena.bool(!preferred.undefined() || !choices.undefined()),
    )?;
    Ok(meta)
}
pub(super) async fn register(c: &C, a: &J) -> Result<J> {
    if !a.get("method")?.is("POST") {
        return Err(error_status("invalid_request", "Method not allowed", 405));
    }
    let header = a.get("contentLength")?.text()?;
    let trimmed = header.trim_start();
    let digits = trimmed
        .strip_prefix('+')
        .unwrap_or(trimmed)
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    if digits.parse::<f64>().unwrap_or(0.0) > 1048576.0 {
        return Err(error_status(
            "invalid_request",
            "Request payload too large, must be under 1 MiB",
            413,
        ));
    }
    let text = match c.effect("request_text", json!({})).await {
        Ok(t) => t,
        Err(Error::Core) => return Err(Error::Core),
        Err(_) => return Err(Error::oauth("invalid_request", "Invalid JSON payload")),
    };
    if text.str()?.len() > 1048576 {
        return Err(error_status(
            "invalid_request",
            "Request payload too large, must be under 1 MiB",
            413,
        ));
    }
    let raw = c.arena.parse_units(&text.str()?).map_err(|e| {
        if matches!(e, Error::Core) {
            e
        } else {
            Error::oauth("invalid_request", "Invalid JSON payload")
        }
    })?;
    let meta = metadata(c, &raw).await.map_err(|e| match e {
        Error::Core => Error::Core,
        Error::Normal { message, .. } => Error::oauth("invalid_client_metadata", message),
        e => e,
    })?;
    let public = meta.get("tokenEndpointAuthMethod")?.is("none");
    let id = random(c, 16).await?;
    let secret = if public {
        c.arena.undef()
    } else {
        random(c, 32).await?
    };
    let hashed = if public {
        c.arena.undef()
    } else {
        hash(c, &secret).await?
    };
    let client = c.arena.obj(vec![("clientId", id.clone())]);
    for key in [
        "redirectUris",
        "clientName",
        "logoUri",
        "clientUri",
        "policyUri",
        "tosUri",
        "jwksUri",
        "i18n",
        "contacts",
        "grantTypes",
        "responseTypes",
    ] {
        client.set(key, &meta.get(key)?)?;
    }
    client.set("registrationDate", &c.arena.num(clock(c).await?))?;
    client.set(
        "tokenEndpointAuthMethod",
        &meta.get("tokenEndpointAuthMethod")?,
    )?;
    if meta.get("authMethodExplicit")?.truth() {
        client.set("authMethodExplicit", &c.arena.bool(true))?;
    }
    if !public {
        client.set("clientSecret", &hashed)?;
    }
    kv_put(
        c,
        storage_key(c, "client", &[&id])?,
        &client,
        &c.arena
            .obj(vec![("expirationTtl", c.arena.num(90.0 * 86400.0))]),
    )
    .await?;
    let out = c.arena.obj(vec![]);
    for (outkey, key) in [
        ("client_id", "clientId"),
        ("redirect_uris", "redirectUris"),
        ("client_name", "clientName"),
        ("logo_uri", "logoUri"),
        ("client_uri", "clientUri"),
        ("policy_uri", "policyUri"),
        ("tos_uri", "tosUri"),
        ("jwks_uri", "jwksUri"),
        ("contacts", "contacts"),
        ("grant_types", "grantTypes"),
        ("response_types", "responseTypes"),
        ("token_endpoint_auth_method", "tokenEndpointAuthMethod"),
        ("client_id_issued_at", "registrationDate"),
    ] {
        out.set(outkey, &client.get(key)?)?;
    }
    for (k, v) in client.get("i18n")?.entries() {
        out.set_units(k, &v)?;
    }
    if secret.truth() {
        out.set("client_secret", &secret)?;
        let date = client.get("registrationDate")?;
        out.set(
            "client_secret_expires_at",
            &c.arena.num(if date.truth() {
                date.number()? + 90.0 * 86400.0
            } else {
                0.0
            }),
        )?;
        out.set("client_secret_issued_at", &date)?;
    }
    json_response(c, 201, out, true)
}
