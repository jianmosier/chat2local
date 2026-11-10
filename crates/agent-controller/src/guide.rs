//! Advisory guide projection. Only completed Bridge tools can create verification evidence.
use crate::{
    Error, Reply, Result, consent, root_mode,
    runtime::{Host, State},
    tools, value,
};
use chat2local_js_value_compat::Document;
use serde_json::{Value, json};
const NAMES: [&str; 10] = [
    "list_devices",
    "list_directory",
    "list_roots",
    "operation_status",
    "propose_write",
    "read_file",
    "terminal_cancel",
    "terminal_execute",
    "terminal_status",
    "write_file",
];
fn names(v: &Value) -> Option<Vec<String>> {
    let a = v.as_array()?;
    if a.len() > 64 {
        return None;
    }
    let mut out = Vec::new();
    for n in a {
        let s = n.as_str()?;
        if s.is_empty()
            || s.len() > 64
            || !s.as_bytes()[0].is_ascii_lowercase()
            || !s
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || out.iter().any(|v| v == s)
        {
            return None;
        }
        out.push(s.into());
    }
    out.sort();
    Some(out)
}
pub fn session(host: &Host, input: &Document) -> Result<Reply> {
    value::fields(input, &["attemptId", "tools"])?;
    let id = consent::identifier(value::string(input, value::prop(input, "attemptId")))?;
    let mut state = host.lock_state();
    let g = value::prop(&state.config, "connectionGuide");
    if g.and_then(|g| value::string(&state.config, value::get(&state.config, g, "id")))
        .as_deref()
        != Some(&id)
    {
        return Err(Error::new(
            409,
            "接入步骤已变化；工具观察未绑定到当前步骤。",
        ));
    }
    let raw = value::prop(input, "tools")
        .ok_or_else(|| Error::new(400, "Invalid session tool observation."))?;
    let tools = names(&serde_json::from_str(&value::subtree(input, raw)?).unwrap_or(Value::Null))
        .ok_or_else(|| Error::new(400, "Invalid session tool observation."))?;
    state.guide_session = Some((
        crate::management::now(),
        json!({"attemptId":id,"tools":tools,"checkedAt":tools::iso_now(),"source":"operator-observed-session"}),
    ));
    drop(state);
    view(host)
}
fn readiness(state: &State, attempt: &Option<String>) -> Value {
    let now = crate::management::now();
    let identity = tools::identity(&state.secrets).ok();
    let remote = state
        .guide_remote
        .as_ref()
        .filter(|(time, v)| {
            now - *time >= -30000.0
                && now - *time < 300000.0
                && identity
                    .as_ref()
                    .is_some_and(|i| v["deviceId"] == i.device && v["origin"] == i.origin)
        })
        .map(|(_, v)| v);
    let session = state
        .guide_session
        .as_ref()
        .filter(|(time, v)| {
            now - *time >= -30000.0
                && now - *time < 300000.0
                && v["attemptId"].as_str() == attempt.as_deref()
        })
        .map(|(_, v)| v);
    let has = |v: &Value, key: &str, name: &str| {
        v[key]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == name))
    };
    let scope = remote
        .map(|r| has(r, "grantedScopes", "files:read") && has(r, "grantedScopes", "files:write"));
    let mut server = remote.cloned().unwrap_or(json!({}));
    server["status"] = json!(if remote.is_some() {
        "observed-on-authenticated-call"
    } else {
        "unknown"
    });
    let mut observed = session.cloned().unwrap_or(json!({}));
    observed["status"] = json!(if session.is_some() {
        "reported"
    } else {
        "unknown"
    });
    observed["missingTools"] = session
        .map(|s| {
            json!(
                ["write_file", "list_devices"]
                    .into_iter()
                    .filter(|n| !has(s, "tools", n))
                    .collect::<Vec<_>>()
            )
        })
        .unwrap_or(Value::Null);
    json!({"expectedTools":NAMES,"server":server,"savedConnection":{"status":"not-observable","message":"本地程序不能读取 ChatGPT 保存或启用的工具清单。"},"session":observed,"latestCallWriteScope":scope,"mayAttemptWrite":remote.is_some_and(|r|has(r,"toolNames","write_file"))&&scope==Some(true)&&session.is_some_and(|s|has(s,"tools","write_file")),"fileAccessGranted":false})
}
pub fn observe(state: &mut State, call: &tools::Call) {
    let Some(d) = &call.diagnostics else { return };
    let Ok(v) = serde_json::from_str::<Value>(&value::serialized(d).unwrap_or_default()) else {
        return;
    };
    let keys = [
        "version",
        "origin",
        "deviceId",
        "serverVersion",
        "toolNames",
        "schemaSha256",
        "grantedScopes",
        "invokedTool",
        "checkedAt",
    ];
    let Some(o) = v.as_object() else { return };
    if o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)) {
        return;
    }
    let Ok(identity) = tools::identity(&state.secrets) else {
        return;
    };
    let hex = |s: &str, n| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if v["version"] != 1
        || v["origin"] != identity.origin
        || v["deviceId"] != identity.device
        || v["invokedTool"] != call.tool
        || !NAMES.contains(&call.tool.as_str())
        || !hex(v["schemaSha256"].as_str().unwrap_or(""), 64)
    {
        return;
    }
    if !server_version(v["serverVersion"].as_str().unwrap_or("")) {
        return;
    }
    let Some(time) = timestamp(v["checkedAt"].as_str().unwrap_or("")) else {
        return;
    };
    if (crate::management::now() - time).abs() > 300000.0 {
        return;
    }
    let Some(tools) = names(&v["toolNames"]) else {
        return;
    };
    if tools.is_empty() {
        return;
    }
    let Some(scopes) = v["grantedScopes"].as_array() else {
        return;
    };
    if scopes.len() > 4 {
        return;
    }
    let mut selected = Vec::new();
    for scope in scopes {
        let Some(s) = scope.as_str() else { return };
        if ![
            "files:read",
            "files:propose",
            "files:write",
            "terminal:execute",
        ]
        .contains(&s)
            || selected.contains(&s)
        {
            return;
        }
        selected.push(s);
    }
    selected.sort();
    let mut checked = v.clone();
    checked["toolNames"] = json!(tools);
    checked["grantedScopes"] = json!(selected);
    state.guide_remote = Some((time, checked));
}
fn server_version(s: &str) -> bool {
    let (main, tail) = s.split_once('-').map_or((s, None), |(a, b)| (a, Some(b)));
    let parts = main.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && tail.is_none_or(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
        })
}
fn timestamp(s: &str) -> Option<f64> {
    // Advisory only: ISO date-only and timezone-bearing ISO timestamps are supported.
    // JavaScript's implementation-defined RFC/locale Date.parse inputs remain unknown;
    // this observation can never authorize a file operation.
    if !s.is_ascii() || s.len() < 10 || s.get(4..5)? != "-" || s.get(7..8)? != "-" {
        return None;
    }
    let n = |a, b| s.get(a..b)?.parse::<i64>().ok();
    let (mut y, m, d) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=days).contains(&d) {
        return None;
    }
    let (mut h, mut mi, mut se, mut ms, mut offset) = (0, 0, 0, 0, 0);
    if s.len() > 10 {
        if s.get(10..11)? != "T" || s.get(13..14)? != ":" || s.get(16..17)? != ":" {
            return None;
        }
        h = n(11, 13)?;
        mi = n(14, 16)?;
        se = n(17, 19)?;
        if h > 23 || mi > 59 || se > 59 {
            return None;
        }
        let mut tail = &s[19..];
        if let Some(f) = tail.strip_prefix('.') {
            let end = f.find(|c: char| !c.is_ascii_digit())?;
            if end == 0 {
                return None;
            }
            let fraction = &f[..end];
            ms = format!("{fraction:0<3}")[..3].parse().ok()?;
            tail = &f[end..];
        }
        if tail != "Z" {
            if tail.len() != 6 || !matches!(tail.as_bytes()[0], b'+' | b'-') || &tail[3..4] != ":" {
                return None;
            }
            let oh = tail[1..3].parse::<i64>().ok()?;
            let om = tail[4..6].parse::<i64>().ok()?;
            if oh > 23 || om > 59 {
                return None;
            }
            offset = (oh * 60 + om) * 60000 * if tail.starts_with('-') { -1 } else { 1 };
        }
    }
    y -= i64::from(m <= 2);
    let era = y.div_euclid(400);
    let year = y - era * 400;
    let month = m + if m > 2 { -3 } else { 9 };
    let day =
        era * 146097 + year * 365 + year / 4 - year / 100 + (153 * month + 2) / 5 + d - 1 - 719468;
    Some((day * 86400000 + h * 3600000 + mi * 60000 + se * 1000 + ms - offset) as f64)
}
pub fn view(host: &Host) -> Result<Reply> {
    let snapshot = host.command(json!({"op":"snapshot"})).ok();
    let state = host.lock_state();
    let config = &state.config;
    let guide = value::prop(config, "connectionGuide").filter(|g| {
        value::number(config, value::get(config, *g, "version")) == Some(1.0)
            && ["id", "rootId"].iter().all(|k| {
                consent::identifier(value::string(config, value::get(config, *g, k))).is_ok()
            })
            && value::string(config, value::get(config, *g, "startedAt")).is_some()
    });
    let attempt = guide.and_then(|g| value::string(config, value::get(config, g, "id")));
    let root = guide.and_then(|g| {
        let id = value::string(config, value::get(config, g, "rootId"));
        value::array(config, value::prop(config, "roots"))
            .unwrap_or_default()
            .into_iter()
            .find(|r| value::string(config, value::get(config, *r, "id")) == id)
    });
    let permitted = root.is_some_and(|r| root_mode(config, r).is_ok_and(|m| m == "direct"));
    let identity = tools::identity(&state.secrets).ok();
    let bound = guide.is_some_and(|g| {
        value::string(config, value::get(config, g, "deviceId")).as_deref()
            == identity.as_ref().map(|i| i.device.as_str())
            && value::string(config, value::get(config, g, "origin"))
                == value::string(config, value::prop(config, "relay"))
    });
    let evidence = if permitted && bound {
        guide.and_then(|g| value::get(config, g, "evidence"))
    } else {
        None
    };
    let ev = |k| {
        evidence
            .and_then(|e| value::get(config, e, k))
            .filter(|v| value::truthy(config, Some(*v)))
    };
    let complete = ["createdAt", "updatedAt", "readBackAt"]
        .iter()
        .all(|k| ev(k).is_some());
    let online = snapshot
        .as_ref()
        .and_then(|s| s["result"]["bridge"]["state"].as_str())
        == Some("connected");
    let previous = value::boolean(config, value::prop(config, "remoteUseConfirmed")) == Some(true);
    let caps = readiness(&state, &attempt);
    let stage =
        if host.faulted() || value::boolean(config, value::prop(config, "paused")) == Some(true) {
            "paused"
        } else if !permitted {
            "choose-folder"
        } else if complete {
            if online { "ready" } else { "reconnecting" }
        } else if identity.is_some() && previous && !online {
            "reconnecting"
        } else if identity.is_some() && online && previous {
            if ev("createdAt").is_some() || caps["mayAttemptWrite"] == true {
                "verify"
            } else {
                "check-tools"
            }
        } else {
            "connect"
        };
    let mut device = tools::description()?;
    if let Some(i) = &identity {
        device["deviceId"] = json!(i.device);
    }
    if let Some(i) = value::string(config, value::prop(config, "installationId")) {
        device["installationId"] = json!(i);
    }
    let mut out=value::parse(json!({"stage":stage,"device":device,"root":null,"attemptId":attempt,"startedAt":guide.and_then(|g|value::string(config,value::get(config,g,"startedAt"))),"directoryGranted":permitted,"online":online,"registered":identity.is_some(),"previousRemoteUse":previous,"setupActive":false,"setup":{},"evidence":{},"complete":complete,"warning":state.guide_warning,"capabilities":caps,"toolCheckPrompt":"","verificationPrompt":""}).to_string().as_bytes())?;
    let mut e = value::parse(b"{}")?;
    for key in ["createdAt", "updatedAt", "readBackAt"] {
        let child = ev(key)
            .map(|id| value::subtree(config, id))
            .transpose()?
            .unwrap_or("null".into());
        let id = e.import(value::parse(child.as_bytes())?, usize::MAX)?;
        e.set_property(e.root(), key.encode_utf16().collect(), id)?;
    }
    attach(&mut out, "evidence", e)?;
    if let Some(r) = root {
        let mut projection = value::parse(b"{}")?;
        for key in ["id", "path", "label"] {
            if let Some(id) = value::get(config, r, key) {
                attach(
                    &mut projection,
                    key,
                    value::parse(value::subtree(config, id)?.as_bytes())?,
                )?;
            }
        }
        value::put(
            &mut projection,
            "writeMode",
            value::text(&root_mode(config, r)?),
        )?;
        attach(&mut out, "root", projection)?;
        if permitted {
            let id = value::string(config, value::get(config, r, "id")).unwrap_or_default();
            let label = value::string(config, value::get(config, r, "label")).unwrap_or_default();
            let name = device["name"].as_str().unwrap_or("本机");
            let device_id = identity.as_ref().map(|i| i.device.as_str());
            let request = attempt.as_deref().unwrap();
            let check = format!(
                "只检查现有 chat2local 的接入能力，不创建或修改文件。\n目标：{name}；deviceId：{}；rootId：{id}。\n先列出当前会话实际提供的 chat2local 工具名，明确是否有 write_file、list_devices；不要把服务端声明当成当前会话已经加载。再用现有 list_roots 核对目标、目录权限和返回的 connectionDiagnostics（服务端工具目录及本次 OAuth scopes）。若未返回诊断字段，标记未知，不自行推定。分别报告服务端声明、ChatGPT连接保存/启用的工具（无法访问则未知）、当前会话工具、当前调用的 files:write 权限。保持目录授权和原插件不变，不改用 DevSpace 或 propose_write 写文件。",
                device_id.unwrap_or("待核对")
            );
            let created =
                format!("chat2local connection check\nrequest: {request}\nstage: created\n");
            let updated =
                format!("chat2local connection check\nrequest: {request}\nstage: updated\n");
            let phase = if ev("updatedAt").is_some() {
                "已观察到创建和修改，只需用 read_file 读回核对下面的最终内容。"
            } else if ev("createdAt").is_some() {
                "已观察到创建；先读回检查当前内容，再完成修改和读回，不重复创建。"
            } else {
                "先用 list_roots 核对目标，再创建、修改并读回以下专用测试文件。"
            };
            let prompt = format!(
                "先确认当前会话实际提供 write_file；缺少时只报告工具缺失，不开始写入，也不更改目录授权。\n通过唯一的 chat2local 插件验证读写。\n目标电脑：{name}；deviceId：{}。\n目录：{label}；rootId：{id}。\n文件：chat2local-check-{request}.txt\n{phase}\n创建内容（包含末尾换行）：\n{}\n最终内容（包含末尾换行）：\n{}\n仅用 write_file（创建 expectedHash=null；修改使用 read_file 返回的当前哈希），再用 read_file 核对。仅修改上述专用文件；已存在时先读回，内容不匹配就停止，不覆盖。不要使用 DevSpace、终端或 propose_write 代替实际插件读写。不支持 write_file 或缺权限时报告原始阻塞，不重新创建插件、不改权限。",
                device_id.unwrap_or("请从 list_devices 核对本机"),
                json!(created),
                json!(updated)
            );
            value::put(&mut out, "toolCheckPrompt", value::text(&check))?;
            value::put(&mut out, "verificationPrompt", value::text(&prompt))?;
        }
    }
    consent::document(out)
}
fn attach(doc: &mut Document, key: &str, child: Document) -> Result<()> {
    let id = doc.import(child, usize::MAX)?;
    doc.set_property(doc.root(), key.encode_utf16().collect(), id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn advisory_iso_and_version_vectors() {
        for v in ["1.2.3", "0.1.0-alpha.28", "01.2.3-A1.9"] {
            assert!(server_version(v));
        }
        for v in ["1.2.3-", "1.2.3-a-b", "1.2", "v1.2.3", "1.2.3+build"] {
            assert!(!server_version(v));
        }
        assert_eq!(timestamp("1970-01-01T00:00:00.000Z"), Some(0.0));
        assert_eq!(timestamp("1970-01-01"), Some(0.0));
        assert_eq!(timestamp("1970-01-01T08:00:00+08:00"), Some(0.0));
        assert_eq!(timestamp("1969-12-31T19:00:00-05:00"), Some(0.0));
        assert_eq!(timestamp("1970-01-01T00:00:00.1Z"), Some(100.0));
        assert!(timestamp("2024-02-29").is_some());
        for v in [
            "2023-02-29",
            "2024-02-30",
            "2024-13-01",
            "2024-01-01T25:00:00Z",
            "2024-01-01T00:00:00+24:00",
            "Thu, 01 Jan 1970 00:00:00 GMT",
        ] {
            assert!(timestamp(v).is_none(), "{v}");
        }
    }
}
