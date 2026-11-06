use chat2local_protocol::{Failure, Operation, Request, Result, RootKind};
use std::collections::HashSet;

pub fn forbidden_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        ".git",
        ".ssh",
        ".aws",
        ".azure",
        ".kube",
        ".gnupg",
        ".npmrc",
        ".netrc",
        ".gitconfig",
        "node_modules",
        "auth.json",
    ]
    .contains(&n.as_str())
        || [".env", ".dev.vars", "credentials"]
            .iter()
            .any(|p| n == *p || n.starts_with(&format!("{p}.")))
        || ["id_rsa", "id_ed25519", ".chat2local-"]
            .iter()
            .any(|p| n.starts_with(p))
        || [".pem", ".key", ".p12", ".pfx"]
            .iter()
            .any(|p| n.ends_with(p))
}

pub fn relative_parts(input: &str, allow_root: bool) -> Result<Vec<&str>> {
    if allow_root && (input == "." || input.is_empty()) {
        return Ok(vec![]);
    }
    if input.encode_utf16().count() > 1024
        || input.starts_with(['/', '\\'])
        || input
            .chars()
            .any(|c| c == ':' || c <= '\u{1f}' || c == '\u{7f}')
    {
        return Err(Failure::new(
            "EPATH",
            "Only a safe relative path is allowed.",
        ));
    }
    let parts: Vec<_> = input.split(['/', '\\']).collect();
    if parts.iter().any(|p| {
        let n = p.split('.').next().unwrap_or("").to_ascii_lowercase();
        let reserved = ["con", "prn", "aux", "nul"].contains(&n.as_str())
            || (n.len() == 4
                && (n.starts_with("com") || n.starts_with("lpt"))
                && n.as_bytes()[3].is_ascii_digit());
        p.is_empty()
            || *p == "."
            || *p == ".."
            || p.ends_with(['.', ' '])
            || p.contains(['<', '>', '"', '|', '?', '*'])
            || reserved
            || forbidden_name(p)
    }) {
        return Err(Failure::new(
            "EPATH",
            "Path traversal, reserved names, and sensitive files are blocked.",
        ));
    }
    Ok(parts)
}

fn id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn root_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
fn resource(value: &str) -> bool {
    let Some(authority) = value.strip_suffix("/mcp") else {
        return false;
    };
    if let Some(host) = authority.strip_prefix("https://") {
        return !host.is_empty()
            && host.is_ascii()
            && !host.contains(['/', '\\', '@', '?', '#', ' '])
            && !host.chars().any(char::is_control);
    }
    let Some(host) = authority.strip_prefix("http://") else {
        return false;
    };
    ["127.0.0.1", "localhost", "[::1]"].iter().any(|name| {
        host == *name
            || host
                .strip_prefix(&format!("{name}:"))
                .is_some_and(|port| !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()))
    })
}

/// Pure per-request policy: no OS APIs, cached grants, keys, or mutable global context.
pub fn authorize(request: &Request) -> Result<Vec<&str>> {
    let deny = || Failure::new("EACCESS", "Folder access is not authorized.");
    if request.v != 1
        || request.id.len() != 36
        || !request.id.bytes().enumerate().all(|(index, c)| {
            if [8, 13, 18, 23].contains(&index) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
    {
        return Err(Failure::new("EPROTOCOL", "Invalid readonly request."));
    }
    let a = &request.authority;
    let root = &a.root;
    if a.paused || !root_id(&root.id) || root.id != request.args.root_id {
        return Err(deny());
    }
    if (root.kind == RootKind::Account && a.access.is_none())
        || (root.kind == RootKind::Legacy && root.connection_id.is_some())
    {
        return Err(deny());
    }
    if let Some(access) = &a.access
        && (access.version != 1
            || !id(&access.connection_id)
            || !id(&access.device_id)
            || a.device_id.as_deref() != Some(&access.device_id)
            || a.resource.as_deref() != Some(&access.resource)
            || !resource(&access.resource)
            || access.roots.is_empty()
            || access.roots.len() > 50
            || access.scopes.len() > 4
            || !access.scopes.iter().any(|s| s == "files:read")
            || access.scopes.iter().any(|s| {
                ![
                    "files:read",
                    "files:write",
                    "files:propose",
                    "terminal:execute",
                ]
                .contains(&s.as_str())
            })
            || access.scopes.iter().collect::<HashSet<_>>().len() != access.scopes.len()
            || access.roots.iter().any(|s| !root_id(&s.root_id))
            || access
                .roots
                .iter()
                .map(|s| &s.root_id)
                .collect::<HashSet<_>>()
                .len()
                != access.roots.len()
            || !access.roots.iter().any(|s| s.root_id == root.id)
            || (root.kind == RootKind::Account
                && root.connection_id.as_deref() != Some(&access.connection_id)))
    {
        return Err(deny());
    }
    relative_parts(&request.args.path, request.op == Operation::ListDirectory)
}

pub fn authorize_write(write: &chat2local_protocol::WriteRequest) -> Result<Vec<&str>> {
    use chat2local_protocol::{Mode, WriteAuthorization};
    let parts = authorize(&write.request)?;
    let deny = || Failure::new("EACCESS", "Writing is not authorized.");
    let direct = write.authorization == WriteAuthorization::DirectoryDirect;
    let allowed = |mode: &Mode| match mode {
        Mode::ReadOnly => false,
        Mode::Review => !direct,
        Mode::Direct => true,
    };
    if write.request.op != Operation::ReadFile || !allowed(&write.request.authority.root.write_mode)
    {
        return Err(deny());
    }
    if let Some(access) = &write.request.authority.access {
        let share = access
            .roots
            .iter()
            .find(|s| s.root_id == write.request.args.root_id)
            .ok_or_else(deny)?;
        // Matches permittedMode: direct requires both direct modes + write;
        // reviewed writes accept either the resulting direct mode or propose.
        let effective_direct = matches!(share.mode, Mode::Direct)
            && matches!(write.request.authority.root.write_mode, Mode::Direct)
            && access.scopes.iter().any(|s| s == "files:write");
        if !allowed(&share.mode)
            || (!effective_direct
                && (direct || !access.scopes.iter().any(|s| s == "files:propose")))
        {
            return Err(deny());
        }
    }
    if write.operation_id.len() != 36
        || !write.operation_id.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
        || write.content.len() > chat2local_protocol::MAX_FILE_BYTES as usize
        || write.content.contains('\0')
        || write.expected_hash.as_ref().is_some_and(|s| {
            s.len() != 64
                || !s
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
    {
        return Err(Failure::new("EPROTOCOL", "Invalid write request."));
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_contract() {
        for value in [
            "../x",
            "a//b",
            "a/",
            "a.",
            "x ",
            "NUL.txt",
            "cOm0",
            "c:x",
            "/x",
            "a\\..\\b",
            ".env.local",
            "秘密.key",
            "x\0",
        ] {
            assert!(relative_parts(value, false).is_err(), "{value:?}");
        }
        assert!(relative_parts("中文\\ok.txt", false).is_ok());
        assert!(relative_parts(".", true).unwrap().is_empty());
        assert!(relative_parts(".", false).is_err());
        assert!(relative_parts(&"😀".repeat(513), false).is_err());
    }
}
