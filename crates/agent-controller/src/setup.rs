//! Existing-device browser recovery and local installation inspection. General
//! unauthenticated self-service enrollment remains explicitly unsupported.
use crate::{
    Error, Reply, Request, Result,
    runtime::Host,
    workflow::{self, Guard, Save, Slot},
    workflow_value::{Doc, hex_id},
};
use serde_json::json;
use std::sync::Arc;
pub fn origin(host: &Host, profile: &str) -> Result<Option<String>> {
    let s = host.lock_state();
    let secrets = Doc(s.secrets.try_clone()?);
    if let Ok(id) = crate::tools::identity(&s.secrets) {
        return Ok(Some(id.origin));
    }
    if profile == "instance"
        && let Some(inv) = secrets.get("privateInstanceInvitation")?
    {
        return inv
            .s("origin")
            .map(|s| crate::network::origin(&s))
            .transpose();
    }
    Doc(s.config.try_clone()?)
        .s("relay")
        .filter(|s| !s.is_empty())
        .map(|s| crate::network::origin(&s))
        .transpose()
}
fn info(code: &str, message: &str) -> Result<Doc> {
    Doc::json(json!({"ready":false,"code":code,"message":message}))
}
fn install(raw: Option<String>) -> Option<String> {
    let raw = raw?;
    let u = url::Url::parse(&raw).ok()?;
    let parts = u
        .path()
        .trim_end_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    (u.origin().ascii_serialization() == "https://chatgpt.com"
        && u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none()
        && parts.len() == 3
        && ["plugins", "apps"].contains(&parts[1])
        && !parts[2].is_empty()
        && parts[2]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then(|| u.to_string())
}
pub async fn inspect(host: &Arc<Host>, guard: &Guard) -> Result<Doc> {
    let result=async{let Some(origin)=origin(host,"")?else{return info("INSTANCE_REQUIRED","请使用自己实例提供的安装入口，或运行自托管配置向导。程序不会默认连接作者的服务。");};let remote=match workflow::request(host,guard,&origin,"/setup-info",None,"inspect").await{Err(e)if e.status==404=>return info("RELAY_UPDATE_REQUIRED","本地程序已更新，但线上连接服务仍是旧版本。需要维护者同步部署；不用寻找或填写配对码。"),other=>other?};if remote.s("name").as_deref()!=Some("chat2local-relay"){return Err(Error::new(503,"Wrong service."));}
if remote.n("setupVersion")!=Some(1.)||!remote.b("browserHandoff"){return info("RELAY_UPDATE_REQUIRED","本机与线上服务的配对协议不一致，需要维护者同步版本。没有注册设备或发送配对凭据。");}
if remote.b("accountConnections"){if remote.b("accountLoginConfigured"){let mut d=info("ACCOUNT_SIGN_IN","使用原账号连接这台电脑，选择目录后只确认一次。")?;d.put("accountEntryUrl",json!(format!("{origin}/account/add")))?;return Ok(d);}return info("ACCOUNT_CONFIGURATION_REQUIRED","项目的账号登录入口尚未由维护者配置。无需输入密钥或重新授权目录。");}
 let installed=install(remote.s("installUrl"));let enrolled=crate::tools::identity(&host.lock_state().secrets).is_ok();let mut d=if installed.is_none()&&enrolled&&remote.b("developerHandoff"){Doc::json(json!({"ready":true,"code":"DEVELOPER_READY","mode":"developer","message":"可以为已注册的这台电脑完成自动配对；随后回到你已打开的 ChatGPT 授权页确认。无需输入配对码。"}))?}else if installed.is_none()&&remote.b("customConnector"){if !enrolled&&!remote.b("selfService"){info("REGISTRATION_CLOSED","维护者尚未开放新电脑接入；不需要填写管理员密钥。")?}else{Doc::json(json!({"ready":true,"code":"CUSTOM_READY","mode":"custom","message":"本服务支持自定义 MCP 接入，无需等待目录上架。完成本机绑定后，在 ChatGPT 添加服务给出的连接地址并确认授权。"}))?}}else if installed.is_none(){info("PUBLICATION_REQUIRED","公开安装尚未就绪。开发实连测试需要维护者先注册这台电脑；这不是等待上架才能测试，也不需要你填写密钥或配对码。")?}else if !enrolled&&!remote.b("selfService"){info("REGISTRATION_CLOSED","连接服务尚未开放新设备注册。请稍后重试，不需要索取管理员邀请。")?}else{Doc::json(json!({"ready":true,"code":"READY","message":"可以继续到官方页面确认连接。"}))?};d.put("installUrl",json!(installed))?;Ok(d)}.await;
    guard.current(host)?;
    let result = result.unwrap_or(info(
        "SERVICE_UNREACHABLE",
        "暂时无法连接服务。软件会使用已有网络配置；请稍后重试，不需要填写邀请或密钥。",
    )?);
    host.workflows.inner.lock().unwrap().setup_info = result.raw()?;
    Ok(result)
}
fn binding(host: &Host) -> Result<String> {
    let s = host.lock_state();
    let identity = crate::tools::identity(&s.secrets).ok();
    let config = Doc(s.config.try_clone()?);
    let roots = config
        .array("roots")?
        .into_iter()
        .map(|r| {
            Doc::list(vec![
                r.need("id")?,
                r.need("path")?,
                Doc::json(json!(r.mode()?))?,
            ])
        })
        .collect::<Result<_>>()?;
    Doc::list(vec![
        Doc::json(json!(identity.as_ref().map(|i| &i.device)))?,
        Doc::json(json!(identity.as_ref().map(|i| &i.origin)))?,
        config.need("paused")?,
        Doc::list(roots)?,
        Doc::json(json!(host.platform.selection_revision()))?,
    ])?
    .raw()
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn return_url(raw: &str, origin: &str) -> Result<String> {
    let u = url::Url::parse(raw).map_err(|_| workflow::stale())?;
    if raw.encode_utf16().count() > 8192
        || u.origin().ascii_serialization() != origin
        || u.path() != "/authorize"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.query().is_none_or(str::is_empty)
    {
        return Err(Error::new(400, "Invalid authorization continuation."));
    }
    Ok(u.to_string())
}
async fn start(host: &Arc<Host>, mut guard: Guard, recovery: bool) -> Result<Doc> {
    {
        let mut s = host.workflows.inner.lock().unwrap();
        if s.setup {
            return Err(Error::new(
                409,
                "连接正在处理中；不会重复注册或打开配对页。",
            ));
        }
        s.setup = true;
    }
    let result=async{let mut inspected=inspect(host,&guard).await?;if !inspected.b("ready"){inspected.put("ok",json!(false))?;inspected.put("websiteClientVerified",json!(false))?;return Ok(inspected);}let identity=crate::tools::identity(&host.lock_state().secrets).map_err(|_|Error::new(501,"请使用私人实例或账号接入入口。此原生入口尚未实现通用自助注册，没有创建身份。"))?;guard.credential=Some((Slot::Active,identity.clone()));guard.current(host)?;
 let snapshot=host.command(json!({"op":"snapshot"}))?;if snapshot["result"]["bridge"]["state"]!="connected"{host.command(json!({"op":"bridgeStart","hasIdentity":true,"now":crate::management::now() as u64}))?;}let until=tokio::time::Instant::now()+std::time::Duration::from_secs(10);loop{guard.current(host)?;if host.command(json!({"op":"snapshot"}))?["result"]["bridge"]["state"]=="connected"{break;}
if tokio::time::Instant::now()>=until{return Err(Error::new(503,"电脑正在连接服务，请稍后再次点击连接；不会重复注册。"));}tokio::time::sleep(std::time::Duration::from_millis(80)).await;}
 let handoff=workflow::request(host,&guard,&identity.origin,&format!("/device/{}/browser-handoff",identity.device),Some(Doc::object()?),"handoff").await?;let secret=handoff.req("secret")?;if !hex_id(&secret,64)||handoff.n("expiresAt").is_none_or(|t|t<=crate::management::now()){return Err(Error::new(403,"授权链接无效；未打开浏览器。"));}guard.current(host)?;let link=format!("{}/link#{}.{}",identity.origin,identity.device,secret);
 if recovery{return Doc::json(json!({"ok":true,"url":link}));}
 host.platform.browser_workflow(host,&json!({"kind":"relay-handoff","url":link}),guard.clone()).await?;guard.current(host)?;
 let message="已打开本机配对确认页。确认后回到同一浏览器中的 ChatGPT 授权页，完成权限确认。无需配对码；这一步还不是文件调用成功。";inspected.put("code",json!("BROWSER_OPENED"))?;inspected.put("message",json!(message))?;host.workflows.inner.lock().unwrap().setup_info=inspected.raw()?;Doc::json(json!({"ok":true,"stage":"browser-opened","websiteClientVerified":false,"message":message}))}.await;
    host.workflows.inner.lock().unwrap().setup = false;
    result
}
async fn invitation(host: &Arc<Host>, guard: Guard, input: Doc) -> Result<Doc> {
    input.fields(&["url"])?;
    let raw = input.req("url")?;
    if raw.encode_utf16().count() > 4096 {
        return Err(Error::new(400, "Invalid private instance invitation."));
    }
    let u = url::Url::parse(&raw).map_err(|_| workflow::stale())?;
    let origin = crate::network::origin(&u.origin().ascii_serialization())?;
    let fragment = u.fragment().ok_or_else(workflow::stale)?;
    let (a, b) = fragment.split_once('.').ok_or_else(workflow::stale)?;
    if !u.username().is_empty()
        || u.password().is_some()
        || u.path() != "/instance/invite"
        || u.query().is_some()
        || !hex_id(a, 32)
        || !hex_id(b, 64)
    {
        return Err(Error::new(400, "Invalid private instance invitation."));
    }
    let fragment = fragment.to_owned();
    workflow::commit(host,Box::new(move|host|Box::pin(async move{guard.current(&host)?;if host.workflows.setup_active()||host.workflows.active()>1{return Err(Error::new(409,"接入正在处理中，请完成原请求。"));}let mut secrets=Doc(host.lock_state().secrets.try_clone()?);for slot in [Slot::Active,Slot::EnrollmentPending,Slot::AccountEnrollmentPending]{if let Ok(identity)=workflow::identity_at(&secrets.0,slot)&&identity.origin!=origin{return Err(Error::new(409,"已有设备身份属于另一实例，没有覆盖。"));}}secrets.put("privateInstanceInvitation",json!({"origin":origin,"invitation":fragment}))?;workflow::save(&host,guard,Save::Secrets,secrets,vec![]).await?;Doc::json(json!({"imported":true,"origin":origin,"mcpUrl":format!("{origin}/mcp"),"foldersGranted":false}))}))).await
}
pub async fn handle(host: &Arc<Host>, request: Request, input: Option<Doc>) -> Result<Reply> {
    if request.target == "/connect" && request.method == "GET" {
        if request.header("sec-fetch-mode") != "navigate"
            || request.header("sec-fetch-dest") != "document"
        {
            return Err(Error::new(
                403,
                "Open the connection page from the authorization flow.",
            ));
        }
        let bound = binding(host)?;
        let token = crate::random(32)?;
        {
            let mut s = host.workflows.inner.lock().unwrap();
            s.tickets
                .retain(|_, (until, _)| *until > crate::management::now());
            if s.tickets.len() >= 32 {
                return Err(Error::new(429, "连接页面过多，请稍后重试。"));
            }
            s.tickets
                .insert(token.clone(), (crate::management::now() + 300000., bound));
        }
        let config = Doc(host.lock_state().config.try_clone()?);
        let identity = crate::tools::identity(&host.lock_state().secrets).ok();
        let available =
            identity.is_some() && !config.b("paused") && !config.array("roots")?.is_empty();
        let relay = identity.map(|i| i.origin).unwrap_or_default();
        let body = format!(
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>chat2local · 继续连接</title><link rel=\"stylesheet\" href=\"/connect.css\"><script defer src=\"/recovery.js\"></script></head><body><main><header><strong>chat2local</strong><span>本机确认</span></header><section><h1>继续连接这台电脑</h1><p>{}</p><p id=\"recovery-message\" role=\"status\">{}</p><input type=\"hidden\" id=\"recovery-token\" value=\"{}\"><input type=\"hidden\" id=\"recovery-relay\" value=\"{}\"><button id=\"recovery-continue\" {}>确认这台电脑并继续</button><p>此页不能新增目录权限或执行文件操作。</p></section></main></body></html>",
            escape(&chat2local_agent_platform::computer_name().unwrap_or("这台电脑".into())),
            if available {
                "沿用已选文件夹，不重新设置目录权限。确认后自动返回原授权流程，无需配对码。"
            } else {
                "请先在本机连接设备、选择目录并恢复访问。此入口不会注册新电脑。"
            },
            token,
            escape(&relay),
            if available { "" } else { "disabled" }
        );
        return Ok(Reply {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body,
            cookie: Some(format!(
                "c2l_recovery={token}; HttpOnly; SameSite=Strict; Path=/connect; Max-Age=300"
            )),
        });
    }
    let input = input.ok_or_else(workflow::stale)?;
    let target = request.target.clone();
    let recovery = target == "/connect/continue";
    let mut guard = Guard::capture(
        host,
        request.disconnected.clone(),
        target == "/api/setup/inspect",
    )?;
    if recovery {
        input.fields(&["nonce", "confirm", "returnUrl"])?;
        let identity = crate::tools::identity(&host.lock_state().secrets)?;
        if !input.b("confirm")
            || Doc(host.lock_state().config.try_clone()?)
                .array("roots")?
                .is_empty()
        {
            return Err(Error::new(409, "此恢复入口仅沿用原设备和目录。"));
        }
        return_url(&input.req("returnUrl")?, &identity.origin)?;
        let nonce = input.req("nonce")?;
        let cookie = workflow::cookie_value(request.header("cookie"), "c2l_recovery")
            .ok_or_else(workflow::stale)?;
        if !hex_id(&nonce, 64)
            || !hex_id(&cookie, 64)
            || !openssl::memcmp::eq(nonce.as_bytes(), cookie.as_bytes())
        {
            return Err(Error::new(403, "请从本机页面确认连接。"));
        }
        let bound = binding(host)?;
        let ticket = host
            .workflows
            .inner
            .lock()
            .unwrap()
            .tickets
            .remove(&nonce)
            .ok_or_else(workflow::stale)?;
        if ticket.0 <= crate::management::now() || ticket.1 != bound {
            return Err(workflow::stale());
        }
        guard.credential = Some((Slot::Active, identity));
    } else if target != "/api/instance/import-invitation" {
        input.fields(&[])?;
    }
    let owner = host.clone();
    let key = if recovery || target == "/api/setup/start" {
        if host.workflows.setup_active() {
            return Err(Error::new(409, "连接正在处理中。"));
        }
        format!("setup:{}", crate::random(8)?)
    } else {
        format!("setup:{target}")
    };
    let fingerprint = input.digest()?;
    let result = host
        .workflows
        .coalesce(host, key, fingerprint, 16, async move {
            match target.as_str() {
                "/api/setup/inspect" => inspect(&owner, &guard).await,
                "/api/setup/start" | "/connect/continue" => start(&owner, guard, recovery).await,
                "/api/instance/import-invitation" => invitation(&owner, guard, input).await,
                _ => Err(Error::new(404, "Unknown setup route.")),
            }
        })
        .await?;
    workflow::reply(result)
}
