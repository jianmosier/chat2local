use super::*;
fn invalid_client(message: &str, basic: bool) -> Error {
    Error::OAuth {
        code: "invalid_client".into(),
        description: message.encode_utf16().collect(),
        status: 401,
        headers: if basic {
            json!({"WWW-Authenticate":"Basic realm=\"OAuth\""})
        } else {
            json!({})
        },
    }
}
async fn basic(c: &C, header: &J) -> Result<Option<Option<(J, J)>>> {
    if !header.truth() {
        return Ok(None);
    }
    let h = header.text()?;
    let end = h.find([' ', '\t']);
    if !h[..end.unwrap_or(h.len())].eq_ignore_ascii_case("basic") {
        return Ok(None);
    }
    let Some(end) = end else {
        return Ok(Some(None));
    };
    let encoded = h[end..].trim_matches(js_whitespace);
    if encoded.is_empty() || encoded.contains([' ', '\t']) {
        return Ok(Some(None));
    }
    let bytes = match base64(&encoded.encode_utf16().collect::<Vec<_>>()) {
        Ok(b) => b,
        Err(_) => return Ok(Some(None)),
    };
    let Some(colon) = bytes.iter().position(|b| *b == b':') else {
        return Ok(Some(None));
    };
    let decode = |b: &[u8]| {
        let s = c.arena.units(
            b.iter()
                .map(|v| u16::from(if *v == b'+' { b' ' } else { *v }))
                .collect(),
        );
        c.effect("decode_component", json!({"input":s.wire().expect("wire")}))
    };
    let result = async {
        Ok((
            decode(&bytes[..colon]).await?,
            decode(&bytes[colon + 1..]).await?,
        ))
    }
    .await;
    match result {
        Ok(v) => Ok(Some(Some(v))),
        Err(Error::Core) => Err(Error::Core),
        Err(_) => Ok(Some(None)),
    }
}
pub(super) async fn endpoint(c: &C, a: &J) -> Result<J> {
    if !a.get("method")?.is("POST") {
        return Err(error_status("invalid_request", "Method not allowed", 405));
    }
    let content = a.get("contentType")?.text()?;
    if content
        .split(';')
        .next()
        .unwrap_or("")
        .trim_matches(js_whitespace)
        .to_lowercase()
        != "application/x-www-form-urlencoded"
    {
        return Err(Error::oauth(
            "invalid_request",
            "Content-Type must be application/x-www-form-urlencoded",
        ));
    }
    let entries = match c.effect("request_form", json!({})).await {
        Ok(v) => v.array()?,
        Err(Error::Core) => return Err(Error::Core),
        Err(_) => {
            return Err(Error::oauth(
                "invalid_request",
                "Request body must be valid application/x-www-form-urlencoded data",
            ));
        }
    };
    let body = c.arena.obj(vec![]);
    let mut seen: Vec<J> = vec![];
    for row in &entries {
        let row = row.array()?;
        let key = &row[0];
        if seen.iter().any(|s| s.eq(key)) {
            continue;
        }
        seen.push(key.clone());
        let mut values = vec![];
        for e in &entries {
            let e = e.array()?;
            if e[0].eq(key) {
                values.push(e[1].clone());
            }
        }
        if !key.is("resource") && values.len() > 1 {
            return Err(Error::oauth(
                "invalid_request",
                format!("Request parameter \"{}\" must not be repeated", key.text()?),
            ));
        } // Ordinary assignment to __proto__ ignores a primitive form string.
        if !key.is("__proto__") {
            body.set(
                &key.text()?,
                &if values.len() > 1 {
                    c.arena.arr(values)
                } else {
                    values[0].clone()
                },
            )?;
        }
    }
    let credentials = basic(c, &a.get("authorization")?).await?;
    let attempted = credentials.is_some();
    let has = |name: &str| seen.iter().any(|s| s.is(name));
    let (id, secret) = if let Some(creds) = credentials {
        if has("client_id") || has("client_secret") {
            return Err(Error::oauth(
                "invalid_request",
                "Client must not use multiple authentication methods",
            ));
        }
        creds.ok_or_else(|| {
            invalid_client(
                "Client authentication failed: invalid Basic credentials",
                true,
            )
        })?
    } else {
        let secret = body.get("client_secret")?;
        (
            body.get("client_id")?,
            if secret.truth() {
                secret
            } else {
                c.arena.s("")
            },
        )
    };
    if !id.truth() {
        return Err(invalid_client("Client ID is required", attempted));
    }
    let client = kv_get(c, storage_key(c, "client", &[&id])?).await?;
    if !client.truth() {
        return Err(invalid_client("Client not found", attempted));
    }
    let presented = if attempted {
        "client_secret_basic"
    } else if has("client_secret") {
        "client_secret_post"
    } else {
        "none"
    };
    let registered = client.get("tokenEndpointAuthMethod")?;
    let secret_method = |v: &J| v.is("client_secret_basic") || v.is("client_secret_post");
    if !registered.is(presented)
        && !(client.get("authMethodExplicit")?.undefined()
            && secret_method(&registered)
            && secret_method(&c.arena.s(presented)))
    {
        return Err(invalid_client("Client authentication failed", attempted));
    }
    if presented != "none" {
        if !secret.truth() {
            return Err(invalid_client(
                "Client authentication failed: missing client_secret",
                attempted,
            ));
        }
        let registered = client.get("clientSecret")?;
        if !registered.truth() {
            return Err(invalid_client(
                "Client authentication failed: client has no registered secret",
                attempted,
            ));
        }
        if !hash(c, &secret).await?.eq(&registered) {
            return Err(invalid_client(
                "Client authentication failed: invalid client_secret",
                attempted,
            ));
        }
    }
    if !body.get("grant_type")?.truth() && body.get("token")?.truth() {
        return revoke_token(c, &body, &client).await;
    }
    let kind = body.get("grant_type")?;
    if kind.is("authorization_code") {
        code(c, a, &body, &client).await
    } else if kind.is("refresh_token") {
        refresh(c, a, &body, &client).await
    } else if kind.is("urn:ietf:params:oauth:grant-type:jwt-bearer") {
        Err(Error::oauth(
            "unsupported_grant_type",
            "JWT bearer grant is not enabled",
        ))
    } else {
        Err(Error::oauth(
            "unsupported_grant_type",
            "Grant type not supported",
        ))
    }
}
async fn revoke_access(c: &C, id: &J, user: &J, grant: &J, client: &J) -> Result<bool> {
    let key = storage_key(c, "token", &[user, grant, id])?;
    let row = kv_get(c, key.clone()).await?;
    if !row.truth() {
        return Ok(false);
    }
    let embedded = row.get("grant")?;
    let owner = if embedded.nullish() {
        c.arena.undef()
    } else {
        embedded.get("clientId")?
    };
    if !owner.undefined() {
        if !owner.eq(&client.get("clientId")?) {
            return Ok(false);
        }
    } else {
        let row = kv_get(c, storage_key(c, "grant", &[user, grant])?).await?;
        let owner = if row.nullish() {
            c.arena.undef()
        } else {
            row.get("clientId")?
        };
        if !owner.eq(&client.get("clientId")?) {
            return Ok(false);
        }
    }
    kv_delete(c, key).await?;
    Ok(true)
}
async fn revoke_refresh(c: &C, id: &J, user: &J, grant: &J, client: &J) -> Result<bool> {
    let row = kv_get(c, storage_key(c, "grant", &[user, grant])?).await?;
    if !row.truth()
        || !(row.get("refreshTokenId")?.eq(id) || row.get("previousRefreshTokenId")?.eq(id))
        || !row.get("clientId")?.eq(&client.get("clientId")?)
    {
        return Ok(false);
    }
    grant::revoke(c, grant.clone(), user.clone()).await?;
    Ok(true)
}
async fn revoke_token(c: &C, body: &J, client: &J) -> Result<J> {
    let token = body.get("token")?;
    if !token.truth() {
        return Err(Error::oauth(
            "invalid_request",
            "Token parameter is required",
        ));
    }
    let parts = split(c, &token, 58, false)?.array()?;
    if parts.len() == 3 {
        let id = hash(c, &token).await?;
        let (user, grant) = (&parts[0], &parts[1]);
        if body.get("token_type_hint")?.is("refresh_token") {
            if !revoke_refresh(c, &id, user, grant, client).await? {
                revoke_access(c, &id, user, grant, client).await?;
            }
        } else if !revoke_access(c, &id, user, grant, client).await? {
            revoke_refresh(c, &id, user, grant, client).await?;
        }
    }
    response(c, 200, c.arena.s(""), c.arena.obj(vec![]), true)
}
async fn code(c: &C, a: &J, body: &J, client: &J) -> Result<J> {
    let code = body.get("code")?;
    if !code.truth() {
        return Err(Error::oauth(
            "invalid_request",
            "Authorization code is required",
        ));
    }
    let parts = split(c, &code, 58, false)?.array()?;
    if parts.len() != 3 {
        return Err(Error::oauth(
            "invalid_grant",
            "Invalid authorization code format",
        ));
    }
    let (user, id) = (&parts[0], &parts[1]);
    let key = storage_key(c, "grant", &[user, id])?;
    let row = kv_get(c, key.clone()).await?;
    if !row.truth() {
        return Err(Error::oauth(
            "invalid_grant",
            "Grant not found or authorization code expired",
        ));
    }
    let code_hash = hash(c, &code).await?;
    if !row.get("authCodeId")?.truth() || !code_hash.eq(&row.get("authCodeId")?) {
        return Err(Error::oauth("invalid_grant", "Invalid authorization code"));
    }
    if !row.get("clientId")?.eq(&client.get("clientId")?) {
        return Err(Error::oauth("invalid_grant", "Client ID mismatch"));
    }
    if !row.get("authCodeWrappedKey")?.truth() {
        if let Err(Error::Core) = grant::revoke(c, id.clone(), user.clone()).await {
            return Err(Error::Core);
        }
        return Err(Error::oauth(
            "invalid_grant",
            "Authorization code already used",
        ));
    }
    let pkce = row.get("codeChallenge")?.truth();
    let method = pkce_method(&row.get("codeChallengeMethod")?, pkce).map_err(|e| match e {
        Error::Authorization { description, .. } => Error::oauth("invalid_grant", description),
        e => e,
    })?;
    let redirect_uri = body.get("redirect_uri")?;
    let verifier = body.get("code_verifier")?;
    if !redirect_uri.truth() && !pkce {
        return Err(Error::oauth(
            "invalid_request",
            "redirect_uri is required when not using PKCE",
        ));
    }
    if redirect_uri.truth() && !redirect(c, &redirect_uri, &client.get("redirectUris")?).await? {
        return Err(Error::oauth("invalid_grant", "Invalid redirect URI"));
    }
    if !pkce && verifier.truth() {
        return Err(Error::oauth(
            "invalid_request",
            "code_verifier provided for a flow that did not use PKCE",
        ));
    }
    if pkce {
        if !verifier.truth() {
            return Err(Error::oauth(
                "invalid_request",
                "code_verifier is required for PKCE",
            ));
        }
        let calculated = if method.is("S256") {
            c.arena.s(encode_base64(&digest(c, &verifier).await?)
                .replace('+', "-")
                .replace('/', "_")
                .trim_end_matches('='))
        } else {
            verifier
        };
        if !calculated.eq(&row.get("codeChallenge")?) {
            return Err(Error::oauth("invalid_grant", "Invalid PKCE code_verifier"));
        }
    }
    let audience = audience(c, a, &body.get("resource")?, &row.get("resource")?).await?;
    let encryption = unwrap(c, &code, &row.get("authCodeWrappedKey")?).await?;
    let scopes = downscope(c, &body.get("scope")?, &row.get("scope")?)?;
    let props = decrypt(c, &encryption, &row.get("encryptedProps")?).await?;
    let projected = projection(c, &props, &scopes)?;
    let (grant_cipher, grant_key) = encrypt(c, &props).await?;
    row.set("encryptedProps", &grant_cipher)?;
    let (access_cipher, access_key) = encrypt(c, &projected).await?;
    let now = clock(c).await?;
    for k in ["codeChallenge", "codeChallengeMethod", "authCodeWrappedKey"] {
        row.remove(k)?;
    }
    let refresh = join(
        c,
        &c.arena
            .arr(vec![user.clone(), id.clone(), random(c, 32).await?]),
        ":",
    )?;
    let refresh_id = hash(c, &refresh).await?;
    let wrapped = wrap(c, &refresh, &grant_key).await?;
    row.set("refreshTokenId", &refresh_id)?;
    row.set("refreshTokenWrappedKey", &wrapped)?;
    row.set("previousRefreshTokenId", &c.arena.undef())?;
    row.set("previousRefreshTokenWrappedKey", &c.arena.undef())?;
    row.set("expiresAt", &c.arena.num(now + 604800.0))?;
    save_grant(c, key, &row, now).await?;
    let access = join(
        c,
        &c.arena
            .arr(vec![user.clone(), id.clone(), random(c, 32).await?]),
        ":",
    )?;
    let now = clock(c).await?;
    let access_id = hash(c, &access).await?;
    let wrapped = wrap(c, &access, &access_key).await?;
    save_access(
        c,
        &access_id,
        user,
        id,
        now,
        3600.0,
        &audience,
        &scopes,
        wrapped,
        row.get("clientId")?,
        scopes.clone(),
        access_cipher,
    )
    .await?;
    json_response(
        c,
        200,
        c.arena.obj(vec![
            ("access_token", access),
            ("token_type", c.arena.s("bearer")),
            ("expires_in", c.arena.num(3600.0)),
            ("scope", join(c, &scopes, " ")?),
            ("refresh_token", refresh),
            ("resource", audience),
        ]),
        true,
    )
}
pub(super) async fn refresh(c: &C, a: &J, body: &J, client: &J) -> Result<J> {
    let refresh = body.get("refresh_token")?;
    if !refresh.truth() {
        return Err(Error::oauth("invalid_request", "Refresh token is required"));
    }
    let parts = split(c, &refresh, 58, false)?.array()?;
    if parts.len() != 3 {
        return Err(Error::oauth("invalid_grant", "Invalid token format"));
    }
    let (user, id) = (&parts[0], &parts[1]);
    let provided = hash(c, &refresh).await?;
    let key = storage_key(c, "grant", &[user, id])?;
    let row = kv_get(c, key.clone()).await?;
    if !row.truth() {
        return Err(Error::oauth("invalid_grant", "Grant not found"));
    }
    let current = row.get("refreshTokenId")?.eq(&provided);
    if !current && !row.get("previousRefreshTokenId")?.eq(&provided) {
        return Err(Error::oauth("invalid_grant", "Invalid refresh token"));
    }
    if !row.get("clientId")?.eq(&client.get("clientId")?) {
        return Err(Error::oauth("invalid_grant", "Client ID mismatch"));
    }
    let expires = row.get("expiresAt")?;
    if !expires.undefined() && expires.number()? - clock(c).await? < 60.0 {
        return Err(Error::oauth("invalid_grant", "Refresh token has expired"));
    }
    let audience = audience(c, a, &body.get("resource")?, &row.get("resource")?).await?;
    let access = join(
        c,
        &c.arena
            .arr(vec![user.clone(), id.clone(), random(c, 32).await?]),
        ":",
    )?;
    let access_id = hash(c, &access).await?;
    let previous_key = row.get(if current {
        "refreshTokenWrappedKey"
    } else {
        "previousRefreshTokenWrappedKey"
    })?;
    let encryption = unwrap(c, &refresh, &previous_key).await?;
    let scopes = downscope(c, &body.get("scope")?, &row.get("scope")?)?;
    let props = decrypt(c, &encryption, &row.get("encryptedProps")?).await?;
    let projected = projection(c, &props, &scopes)?;
    let (cipher, access_key) = encrypt(c, &projected).await?;
    let now = clock(c).await?;
    let mut ttl: f64 = 3600.0;
    if !expires.undefined() {
        let remaining = expires.number()? - now;
        if remaining < 60.0 {
            return Err(Error::oauth("invalid_grant", "Refresh token has expired"));
        }
        if remaining > 0.0 {
            ttl = ttl.min(remaining)
        }
    }
    let wrapped_access = wrap(c, &access, &access_key).await?;
    let next = join(
        c,
        &c.arena
            .arr(vec![user.clone(), id.clone(), random(c, 32).await?]),
        ":",
    )?;
    let next_id = hash(c, &next).await?;
    let wrapped = wrap(c, &next, &encryption).await?;
    row.set("previousRefreshTokenId", &provided)?;
    row.set("previousRefreshTokenWrappedKey", &previous_key)?;
    row.set("refreshTokenId", &next_id)?;
    row.set("refreshTokenWrappedKey", &wrapped)?;
    save_grant(c, key, &row, now).await?;
    save_access(
        c,
        &access_id,
        user,
        id,
        now,
        ttl,
        &audience,
        &scopes,
        wrapped_access,
        row.get("clientId")?,
        row.get("scope")?,
        cipher,
    )
    .await?;
    json_response(
        c,
        200,
        c.arena.obj(vec![
            ("access_token", access),
            ("token_type", c.arena.s("bearer")),
            ("expires_in", c.arena.num(ttl)),
            ("refresh_token", next),
            ("scope", join(c, &scopes, " ")?),
            ("resource", audience),
        ]),
        true,
    )
}
#[allow(clippy::too_many_arguments)]
async fn save_access(
    c: &C,
    id: &J,
    user: &J,
    grant: &J,
    now: f64,
    ttl: f64,
    audience: &J,
    scopes: &J,
    wrapped: J,
    client: J,
    grant_scope: J,
    cipher: J,
) -> Result<()> {
    let row = c.arena.obj(vec![
        ("id", id.clone()),
        ("grantId", grant.clone()),
        ("userId", user.clone()),
        ("createdAt", c.arena.num(now)),
        ("expiresAt", c.arena.num(now + ttl)),
        ("audience", audience.clone()),
        ("scope", scopes.clone()),
        ("wrappedEncryptionKey", wrapped),
        (
            "grant",
            c.arena.obj(vec![
                ("clientId", client),
                ("scope", grant_scope),
                ("encryptedProps", cipher),
            ]),
        ),
    ]);
    kv_put(
        c,
        storage_key(c, "token", &[user, grant, id])?,
        &row,
        &c.arena.obj(vec![("expirationTtl", c.arena.num(ttl))]),
    )
    .await
    .map_err(storage_error)
}
