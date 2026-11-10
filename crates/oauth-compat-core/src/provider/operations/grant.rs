use super::*;
use std::{cell::RefCell, rc::Rc};

pub(super) async fn list(c: &C, user: J, options: J) -> Result<J> {
    let args = c.arena.obj(vec![(
        "prefix",
        storage_key(c, "grant", &[&user, &c.arena.s("")])?,
    )]);
    if !options.nullish() {
        for k in ["limit", "cursor"] {
            let v = options.get(k)?;
            if !v.undefined() {
                args.set(k, &v)?;
            }
        }
    }
    let page = c.effect("kv_list", json!({"options":args.wire()?})).await?;
    let items: Rc<RefCell<Vec<J>>> = Rc::new(RefCell::new(vec![]));
    let mut tasks = vec![];
    for key in page.get("keys")?.array()? {
        let c = c.clone();
        let items = items.clone();
        let task = c.clone().spawn(async move {
            let row = kv_get(&c, key.get("name")?).await?;
            if row.truth() {
                let item = c.arena.obj(vec![]);
                for k in [
                    "id",
                    "clientId",
                    "userId",
                    "scope",
                    "metadata",
                    "createdAt",
                    "expiresAt",
                    "redirectUri",
                ] {
                    item.set(k, &row.get(k)?)?;
                }
                items.borrow_mut().push(item);
            }
            Ok(c.arena.undef())
        });
        tasks.push(task);
    }
    c.join(tasks, false).await?;
    let output = c.arena.arr(items.borrow().clone());
    Ok(c.arena.obj(vec![
        ("items", output),
        (
            "cursor",
            if page.get("list_complete")?.truth() {
                c.arena.undef()
            } else {
                page.get("cursor")?
            },
        ),
    ]))
}
pub(super) async fn revoke(c: &C, grant: J, user: J) -> Result<J> {
    let mut cursor = c.arena.undef();
    loop {
        let options = c.arena.obj(vec![(
            "prefix",
            storage_key(c, "token", &[&user, &grant, &c.arena.s("")])?,
        )]);
        if cursor.truth() {
            options.set("cursor", &cursor)?;
        }
        let page = c
            .effect("kv_list", json!({"options":options.wire()?}))
            .await?;
        let mut tasks = vec![];
        for key in page.get("keys")?.array()? {
            let c = c.clone();
            tasks.push(
                c.clone()
                    .spawn(async move { kv_delete(&c, key.get("name")?).await }),
            );
        }
        c.join(tasks, false).await?;
        if page.get("list_complete")?.truth() {
            break;
        }
        cursor = page.get("cursor")?;
    }
    kv_delete(c, storage_key(c, "grant", &[&user, &grant])?).await?;
    Ok(c.arena.undef())
}
pub(super) async fn complete(c: &C, a: &J) -> Result<J> {
    let options = a.get("options")?;
    if options.nullish() {
        return Err(Error::normal(
            "TypeError",
            format!(
                "Cannot read properties of {} (reading 'request')",
                if options.undefined() {
                    "undefined"
                } else {
                    "null"
                }
            ),
        ));
    }
    let request = options.get("request")?;
    if request.nullish() {
        return Err(Error::normal(
            "TypeError",
            format!(
                "Cannot destructure property 'clientId' of 'options.request' as it is {}.",
                if request.undefined() {
                    "undefined"
                } else {
                    "null"
                }
            ),
        ));
    }
    let client_id = request.get("clientId")?;
    let redirect_uri = request.get("redirectUri")?;
    if !client_id.truth() || !redirect_uri.truth() {
        return Err(Error::normal(
            "Error",
            "Client ID and Redirect URI are required in the authorization request.",
        ));
    }
    let client = lookup(c, client_id.clone()).await?;
    if !client.truth() || !redirect(c, &redirect_uri, &client.get("redirectUris")?).await? {
        return Err(Error::normal(
            "Error",
            "Invalid redirect URI. The redirect URI provided does not match any registered URI for this client.",
        ));
    }
    // Response validation precedes resource, and PKCE follows it.
    let only_response = request.spread()?;
    only_response.set("codeChallenge", &c.arena.s("present"))?;
    only_response.set("codeChallengeMethod", &c.arena.s("S256"))?;
    validate_auth(&only_response, &client)?;
    let given = request.get("resource")?;
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
    validate_pkce(&request, &client)?;
    let user = options.get("userId")?;
    let mut old = vec![];
    if !matches!(
        options.get("revokeExistingGrants")?.val(),
        Value::Bool(false)
    ) {
        let batch = options.get("revokeExistingGrantsBatchSize")?;
        let batch = if batch.undefined() {
            50.0
        } else {
            if !matches!(batch.val(),Value::Number(n) if n.is_finite()&&n.fract()==0.0&&n>=1.0) {
                return Err(Error::normal(
                    "Error",
                    "revokeExistingGrantsBatchSize must be a positive integer.",
                ));
            }
            batch.number()?.min(1000.0)
        };
        let cimd = client_id.text()?.starts_with("https://");
        let mut cursor = c.arena.undef();
        loop {
            let page = list(
                c,
                user.clone(),
                c.arena
                    .obj(vec![("cursor", cursor), ("limit", c.arena.num(batch))]),
            )
            .await?;
            for grant in page.get("items")?.array()? {
                if grant.get("clientId")?.eq(&client_id)
                    && (!cimd || grant.get("redirectUri")?.eq(&redirect_uri))
                {
                    old.push(grant.get("id")?);
                }
            }
            cursor = page.get("cursor")?;
            if !cursor.truth() {
                break;
            }
        }
    }
    let id = random(c, 16).await?;
    let (cipher, key) = encrypt(c, &options.get("props")?).await?;
    let now = clock(c).await?;
    let secret = random(c, 32).await?;
    let code = join(c, &c.arena.arr(vec![user.clone(), id.clone(), secret]), ":")?;
    let code_id = hash(c, &code).await?;
    let wrapped = wrap(c, &code, &key).await?;
    let row = c.arena.obj(vec![
        ("id", id.clone()),
        ("clientId", client_id),
        ("userId", user.clone()),
        ("scope", options.get("scope")?),
        ("metadata", options.get("metadata")?),
        ("encryptedProps", cipher),
        ("createdAt", c.arena.num(now)),
        ("authCodeId", code_id),
        ("authCodeWrappedKey", wrapped),
        ("codeChallenge", request.get("codeChallenge")?),
        ("codeChallengeMethod", request.get("codeChallengeMethod")?),
        ("resource", target),
        ("redirectUri", redirect_uri.clone()),
    ]);
    kv_put(
        c,
        storage_key(c, "grant", &[&user, &id])?,
        &row,
        &c.arena.obj(vec![("expirationTtl", c.arena.num(600.0))]),
    )
    .await?;
    let mut sets = vec![c.arena.arr(vec![c.arena.s("code"), code])];
    for (k, name) in [("state", "state"), ("issuer", "iss")] {
        let value = request.get(k)?;
        if value.truth() {
            sets.push(c.arena.arr(vec![c.arena.s(name), value]));
        }
    }
    let redirect_to = c
        .effect(
            "url_set",
            json!({"input":redirect_uri.wire()?,"sets":c.arena.arr(sets).wire()?}),
        )
        .await?;
    let mut tasks = vec![];
    for grant in old {
        let c = c.clone();
        let user = user.clone();
        tasks.push(
            c.clone()
                .spawn(async move { revoke(&c, grant, user).await }),
        );
    }
    c.join(tasks, true).await?;
    Ok(c.arena.obj(vec![("redirectTo", redirect_to)]))
}
