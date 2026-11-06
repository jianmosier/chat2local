use crate::{Reply, Request};
pub fn asset(request: &Request) -> Option<Reply> {
    if request.method != "GET" {
        return None;
    }
    let (content_type, body) = match request.target.as_str() {
        "/" | "/folders" => ("text/html; charset=utf-8", include_str!("../ui/index.html")),
        "/native-panel.js" => (
            "text/javascript; charset=utf-8",
            include_str!("../ui/panel.js"),
        ),
        "/native-panel.css" => ("text/css; charset=utf-8", include_str!("../ui/panel.css")),
        "/account-connect.js" | "/instance-connect.js" => (
            "text/javascript; charset=utf-8",
            include_str!("../../../src/agent/ui/account-connect.js"),
        ),
        "/connect.css" => (
            "text/css; charset=utf-8",
            include_str!("../../../src/agent/ui/connect.css"),
        ),
        "/shares" => (
            "text/html; charset=utf-8",
            include_str!("../../../src/agent/ui/folders.html"),
        ),
        "/folders.js" => (
            "text/javascript; charset=utf-8",
            include_str!("../../../src/agent/ui/folders.js"),
        ),
        "/folders.css" => (
            "text/css; charset=utf-8",
            include_str!("../../../src/agent/ui/folders.css"),
        ),
        "/lifecycle.js" => (
            "text/javascript; charset=utf-8",
            include_str!("../../../src/agent/ui/lifecycle.js"),
        ),
        "/installation.js" => (
            "text/javascript; charset=utf-8",
            include_str!("../../../src/shared/installation.mjs"),
        ),
        "/recovery.js" => (
            "text/javascript; charset=utf-8",
            include_str!("../ui/recovery.js"),
        ),
        _ => return None,
    };
    Some(Reply {
        status: 200,
        content_type,
        body: body.into(),
        cookie: None,
    })
}
