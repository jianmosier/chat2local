//! Directory discovery takes an explicit environment/home snapshot. A target
//! platform affects only path spelling; it never selects an encryption backend.
use crate::{Error, Result};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
pub struct Location<'a> {
    pub env: &'a BTreeMap<String, String>,
    pub platform: &'a str,
    pub home: &'a str,
}
fn nonempty<'a>(env: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(key).map(String::as_str).filter(|x| !x.is_empty())
}
fn normalize_parts(text: &str, rooted: bool) -> String {
    let mut parts = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            ".." if !rooted => parts.push(part),
            ".." => {}
            _ => parts.push(part),
        }
    }
    parts.join("/")
}
fn join(parts: &[&str], windows: bool) -> String {
    let raw = parts
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("/");
    if raw.is_empty() {
        return ".".into();
    }
    let raw = if windows { raw.replace('\\', "/") } else { raw };
    let trailing = raw.ends_with('/');
    let (prefix, tail, rooted) = if windows && raw.starts_with("//") && !raw.starts_with("///") {
        let segments = raw[2..]
            .split('/')
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        if segments.len() >= 2 {
            let prefix = format!("//{}/{}/", segments[0], segments[1]);
            let start = raw.find(segments[0]).unwrap() + segments[0].len();
            let end = start + raw[start..].find(segments[1]).unwrap() + segments[1].len();
            (prefix, &raw[end..], true)
        } else {
            (String::from("/"), raw.trim_start_matches('/'), true)
        }
    } else if windows
        && raw.as_bytes().get(1) == Some(&b':')
        && raw.as_bytes()[0].is_ascii_alphabetic()
    {
        let rooted = raw.as_bytes().get(2) == Some(&b'/');
        (
            format!("{}{}", &raw[..2], if rooted { "/" } else { "" }),
            &raw[2..],
            rooted,
        )
    } else if raw.starts_with('/') {
        (String::from("/"), raw.trim_start_matches('/'), true)
    } else {
        (String::new(), raw.as_str(), false)
    };
    let normalized = normalize_parts(tail, rooted);
    let mut output = prefix;
    if !normalized.is_empty() {
        output.push_str(&normalized);
    } else if !rooted {
        output.push('.');
    }
    if trailing && !output.ends_with('/') {
        output.push('/');
    }
    if windows {
        output.replace('/', "\\")
    } else {
        output
    }
}
pub fn state_directory(options: &Location<'_>) -> String {
    if let Some(value) = nonempty(options.env, "CHAT2LOCAL_STATE_DIR") {
        return value.to_owned();
    }
    match options.platform {
        "win32" => join(
            &[
                &nonempty(options.env, "LOCALAPPDATA")
                    .map(str::to_owned)
                    .unwrap_or_else(|| join(&[options.home, "AppData", "Local"], true)),
                "Chat2Local",
            ],
            true,
        ),
        "darwin" => join(
            &[options.home, "Library", "Application Support", "Chat2Local"],
            false,
        ),
        _ => join(
            &[
                &nonempty(options.env, "XDG_STATE_HOME")
                    .map(str::to_owned)
                    .unwrap_or_else(|| join(&[options.home, ".local", "state"], false)),
                "chat2local",
            ],
            false,
        ),
    }
}
pub fn existing_state_directory(options: &Location<'_>) -> Result<String> {
    let preferred = state_directory(options);
    if nonempty(options.env, "CHAT2LOCAL_STATE_DIR").is_some() || options.platform == "win32" {
        return Ok(preferred);
    }
    let legacy = join(
        &[options.home, ".local", "share", "Chat2Local"],
        cfg!(windows),
    );
    let current = has_state(Path::new(&preferred))?;
    let previous = has_state(Path::new(&legacy))?;
    if current && previous && preferred != legacy {
        return Err(Error::new(
            "ECONFLICT",
            "Two state directories exist; select the original directory. No merge or reset was performed.",
        ));
    }
    Ok(if previous { legacy } else { preferred })
}
fn has_state(path: &Path) -> Result<bool> {
    for file in ["settings.json", "vault.json", "session.json"] {
        match std::fs::symlink_metadata(path.join(file)) {
            Ok(_) => return Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}
pub fn legacy_directory(home: &str) -> PathBuf {
    PathBuf::from(join(
        &[home, ".local", "share", "Chat2Local"],
        cfg!(windows),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn join_keeps_target_spelling_and_relative_paths() {
        assert_eq!(
            join(&["C:", "AppData", "Local"], true),
            "C:\\AppData\\Local"
        );
        assert_eq!(
            join(&["//server/share/a/..", "Chat2Local"], true),
            "\\\\server\\share\\Chat2Local"
        );
        assert_eq!(
            join(&["/home/a/../b", ".local", "state"], false),
            "/home/b/.local/state"
        );
        assert_eq!(join(&["../a/../", "b"], false), "../b");
    }
}
