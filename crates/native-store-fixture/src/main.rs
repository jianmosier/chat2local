//! Test fixture only. Never packaged as a production host/backend.
use chat2local_native_store::{
    Document, Error, Result, Store, Value, compact, json,
    location::{self, Location},
    same_directory,
};
use serde_json::{Value as Wire, json as wire};
use std::{
    collections::BTreeMap,
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
};
const FRAME: usize = 16 * 1024 * 1024;
fn required<'a>(value: &'a Wire, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| Error::new("EFIXTURE", format!("Missing {key}.")))
}
fn inside(root: &Path, relative: &str) -> Result<PathBuf> {
    let p = Path::new(relative);
    if p.is_absolute()
        || p.components().any(|c| {
            !matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return Err(Error::new("EFIXTURE", "Fixture-relative path required."));
    }
    Ok(root.join(p))
}
fn target(store: &Store, target: &str, key: &str) -> Result<Document> {
    match target {
        "config" => Ok(store.load()?.config),
        "secrets" => Ok(store.load()?.secrets),
        "session" => store.read_session(),
        "private" => store
            .read_private_record(key)?
            .ok_or_else(|| Error::new("ENOENT", "Missing private record.")),
        _ => Err(Error::new("EFIXTURE", "Invalid target.")),
    }
}
fn save(store: &Store, target: &str, key: &str, value: &Document) -> Result<()> {
    match target {
        "config" => store.save_config(value),
        "secrets" => store.save_secrets(value),
        "session" => store.save_session(value),
        "private" => store.save_private_record(key, value),
        _ => Err(Error::new("EFIXTURE", "Invalid target.")),
    }
}
fn command(store: &Store, input: Wire) -> Result<Wire> {
    let key = input["key"].as_str().unwrap_or("");
    match required(&input, "op")? {
        "load" => {
            let value = store.load()?;
            Ok(wire!({"configJson":compact(&value.config)?,"secretsJson":compact(&value.secrets)?}))
        }
        "read" => {
            let target = required(&input, "target")?;
            if target == "private" {
                return Ok(match store.read_private_record(key)? {
                    Some(doc) => wire!({"missing":false,"json":compact(&doc)?}),
                    None => wire!({"missing":true}),
                });
            }
            Ok(wire!({"json":compact(&self::target(store,target,key)?)?}))
        }
        "save" => {
            let value = json(required(&input, "json")?.as_bytes())?;
            save(store, required(&input, "target")?, key, &value)?;
            Ok(wire!({"saved":true}))
        }
        "patch" => {
            let name = required(&input, "target")?;
            let mut doc = target(store, name, key)?;
            let path: Vec<Vec<u16>> = serde_json::from_value(input["path"].clone())
                .map_err(|_| Error::new("EFIXTURE", "UTF16 key path required."))?;
            let (last, parents) = path
                .split_last()
                .ok_or_else(|| Error::new("EFIXTURE", "Empty patch path."))?;
            let mut id = doc.root();
            for part in parents {
                id = match doc.value(id)? {
                    Value::Array(items) => {
                        let index = String::from_utf16(part)
                            .ok()
                            .and_then(|s| s.parse::<usize>().ok())
                            .ok_or_else(|| Error::new("EFIXTURE", "Invalid index."))?;
                        *items
                            .get(index)
                            .ok_or_else(|| Error::new("EFIXTURE", "Missing index."))?
                    }
                    _ => doc
                        .get_property(id, part)?
                        .ok_or_else(|| Error::new("EFIXTURE", "Missing property."))?,
                };
            }
            if input["remove"] == true {
                doc.remove_property(id, last)?;
            } else {
                let value = doc.import(json(required(&input, "json")?.as_bytes())?, usize::MAX)?;
                doc.set_property(id, last.clone(), value)?;
            }
            save(store, name, key, &doc)?;
            Ok(wire!({"json":compact(&doc)?}))
        }
        "path" => Ok(wire!({"path":store.private_record_path(key)?})),
        "location" => {
            let env: BTreeMap<String, String> = serde_json::from_value(input["env"].clone())
                .map_err(|_| Error::new("EFIXTURE", "Environment object required."))?;
            let options = Location {
                env: &env,
                platform: required(&input, "platform")?,
                home: required(&input, "home")?,
            };
            Ok(wire!({"path":location::state_directory(&options)}))
        }
        "existing" => {
            let home = inside(store.directory(), input["home"].as_str().unwrap_or("home"))?;
            let home = home
                .to_str()
                .ok_or_else(|| Error::new("EFIXTURE", "Invalid home."))?;
            let mut env = BTreeMap::new();
            for (key, value) in input["env"]
                .as_object()
                .ok_or_else(|| Error::new("EFIXTURE", "Environment object required."))?
            {
                if !["CHAT2LOCAL_STATE_DIR", "LOCALAPPDATA", "XDG_STATE_HOME"]
                    .contains(&key.as_str())
                {
                    return Err(Error::new("EFIXTURE", "Invalid environment key."));
                }
                env.insert(
                    key.clone(),
                    inside(
                        store.directory(),
                        value
                            .as_str()
                            .ok_or_else(|| Error::new("EFIXTURE", "Invalid path."))?,
                    )?
                    .to_string_lossy()
                    .into_owned(),
                );
            }
            Ok(
                wire!({"path":location::existing_state_directory(&Location{env:&env,platform:required(&input,"platform")?,home})?}),
            )
        }
        "same" => Ok(
            wire!({"same":same_directory(&inside(store.directory(),required(&input,"first")?)?,&inside(store.directory(),required(&input,"second")?)?)?}),
        ),
        _ => Err(Error::new("EFIXTURE", "Unsupported fixture command.")),
    }
}
fn main() -> std::io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 || args[0] != "--state-dir" {
        return Err(std::io::Error::other(
            "Explicit synthetic --state-dir is required.",
        ));
    }
    let root = PathBuf::from(&args[1]);
    if !root.is_absolute()
        || std::fs::read(root.join(".chat2local-native-store-fixture"))?
            != b"synthetic-native-store-fixture\n"
    {
        return Err(std::io::Error::other(
            "Synthetic fixture marker is required.",
        ));
    }
    let store = Store::new(root);
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let n = Read::by_ref(&mut input)
            .take((FRAME + 2) as u64)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        if line.len() > FRAME + 1 || !line.ends_with(b"\n") {
            return Err(std::io::Error::other("Invalid fixture frame."));
        }
        let result = serde_json::from_slice(&line)
            .map_err(|_| Error::new("EFIXTURE", "Invalid frame JSON."))
            .and_then(|v| command(&store, v));
        let response = match result {
            Ok(value) => wire!({"ok":true,"value":value}),
            Err(error) => wire!({"ok":false,"code":error.code,"message":error.message}),
        };
        serde_json::to_writer(&mut output, &response)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}
