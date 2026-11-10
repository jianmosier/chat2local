//! Legacy local Store compatibility. Explicit directory; no controller/backend
//! selection, subprocesses, cross-file transaction, permission repair or replay.
mod codec;
mod fs;
mod write_fence;
pub use write_fence::{assert_write_fence_clear, check_fence};
pub mod location;
use chat2local_js_value_compat::Limits;
pub use chat2local_js_value_compat::{Document, Value, ValueId};
pub use fs::same_directory;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}
impl Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn invalid(message: &str) -> Self {
        Self::new("EINVALID", message)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new(
            if error.kind() == std::io::ErrorKind::NotFound {
                "ENOENT"
            } else {
                "EIO"
            },
            error.to_string(),
        )
    }
}
impl From<chat2local_js_value_compat::Error> for Error {
    fn from(error: chat2local_js_value_compat::Error) -> Self {
        Self::new("EJSON", error.to_string())
    }
}
pub type Result<T> = std::result::Result<T, Error>;
// Legacy settings/vault had no arbitrary document-size/depth ceiling. Bounded
// IPC callers enforce their own input bounds; the reusable Store does not turn
// large existing settings into a missing/default record.
const JSON_LIMITS: Limits = Limits {
    input_units: usize::MAX,
    nodes: usize::MAX,
    depth: usize::MAX,
    output_bytes: usize::MAX,
};
pub fn json(bytes: &[u8]) -> Result<Document> {
    Ok(Document::parse_str(
        &String::from_utf8_lossy(bytes),
        JSON_LIMITS,
    )?)
}
pub fn compact(doc: &Document) -> Result<String> {
    doc.stringify(JSON_LIMITS)?
        .ok_or_else(|| Error::invalid("Undefined cannot be stored."))
}
pub fn truthy(doc: &Document) -> Result<bool> {
    Ok(match doc.value(doc.root())? {
        Value::Undefined | Value::Null => false,
        Value::Bool(v) => *v,
        Value::Number(v) => *v != 0.0 && !v.is_nan(),
        Value::String(v) => !v.is_empty(),
        _ => true,
    })
}
fn property<'a>(doc: &'a Document, key: &str) -> Result<Option<&'a Value>> {
    let Value::Object(obj) = doc.value(doc.root())? else {
        return Ok(None);
    };
    obj.get(&key.encode_utf16().collect::<Vec<_>>())
        .map(|id| doc.value(id).map_err(Into::into))
        .transpose()
}
fn validate_settings(doc: &Document) -> Result<()> {
    if !matches!(property(doc,"version")?, Some(Value::Number(v)) if *v == 1.0)
        || !matches!(property(doc, "roots")?, Some(Value::Array(_)))
        || !matches!(property(doc, "paused")?, Some(Value::Bool(_)))
    {
        return Err(Error::invalid("Unsupported settings format."));
    }
    Ok(())
}
fn read_json(path: &Path) -> Result<Document> {
    json(&std::fs::read(path)?)
}
static TEMP: AtomicU64 = AtomicU64::new(1);
pub type PublicationScope<'a> = dyn Fn(&mut dyn FnMut() -> Result<()>) -> Result<()> + 'a;
fn atomic_json(path: &Path, doc: &Document, guard: &dyn Fn() -> Result<()>) -> Result<()> {
    atomic_json_scoped(path, doc, guard, &|work| work())
}
fn atomic_json_scoped(
    path: &Path,
    doc: &Document,
    guard: &dyn Fn() -> Result<()>,
    admission: &crate::PublicationScope<'_>,
) -> Result<()> {
    guard()?;
    fs::mkdir(
        path.parent()
            .ok_or_else(|| Error::invalid("Missing parent."))?,
    )?;
    let sequence = TEMP
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_add(1))
        .map_err(|_| Error::invalid("Temporary identity exhausted."))?;
    let mut temp = path.as_os_str().to_os_string();
    temp.push(format!(".{}-{sequence}.tmp", std::process::id()));
    let temp = PathBuf::from(temp);
    guard()?;
    let mut file = fs::create(&temp)?;
    let result = (|| {
        guard()?;
        file.write_all(codec::pretty(&compact(doc)?).as_bytes())?;
        fs::publish_scoped(&file, &temp, path, guard, admission)?;
        Ok(())
    })();
    drop(file);
    if guard().is_ok() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|x| (x.as_secs_f64() * 1000.0).floor())
        .unwrap_or(0.0)
}
fn hex(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn onboarding(key: &str) -> bool {
    ["onboarding-flow-", "onboarding-intent-"]
        .iter()
        .any(|prefix| {
            key.strip_prefix(prefix)
                .is_some_and(|tail| tail.len() == 32 && hex(tail))
        })
}
fn terminal(key: &str) -> bool {
    key.strip_prefix("terminal-").is_some_and(|tail| {
        let parts: Vec<_> = tail.split('-').collect();
        parts.len() == 5
            && parts
                .iter()
                .zip([8, 4, 4, 4, 12])
                .all(|(p, n)| p.len() == n && hex(p))
    })
}
pub struct Store {
    directory: PathBuf,
    guard: Option<std::sync::Arc<dyn Fn() -> Result<()> + Send + Sync>>,
}
pub struct Loaded {
    pub config: Document,
    pub secrets: Document,
}
impl Store {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            guard: None,
        }
    }
    pub fn with_guard(
        mut self,
        guard: std::sync::Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Self {
        self.guard = Some(guard);
        self
    }
    pub fn check_owner(&self) -> Result<()> {
        if let Some(guard) = &self.guard {
            guard()?;
        }
        Ok(())
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn append_audit(&self, event: &Document) -> Result<()> {
        self.check_owner()?;
        fs::mkdir(&self.directory)?;
        fs::parent_safe(&self.directory)?;
        let path = self.directory.join("audit.jsonl");
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                fs::open_private(&path, u64::MAX)?;
                if meta.len() > 1024 * 1024 {
                    self.check_owner()?;
                    fs::rename(&path, &self.directory.join("audit.jsonl.previous"), &|| {
                        self.check_owner()
                    })?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.check_owner()?;
        let mut file = fs::append_private(&path)?;
        let line = compact(event)? + "\n";
        self.check_owner()?;
        file.write_all(line.as_bytes())?;
        Ok(())
    }
    pub fn load(&self) -> Result<Loaded> {
        self.check_owner()?;
        fs::mkdir(&self.directory)?;
        let config = match read_json(&self.directory.join("settings.json")) {
            Ok(v) => v,
            Err(e) if e.code == "ENOENT" => {
                json(br#"{"version":1,"roots":[],"paused":false,"startup":false,"relay":""}"#)?
            }
            Err(e) => return Err(e),
        };
        validate_settings(&config)?;
        let secrets = match self.read_sealed("vault.json") {
            Ok(v) => v,
            Err(e) if e.code == "ENOENT" => json(b"{}")?,
            Err(e) => return Err(e),
        };
        Ok(Loaded { config, secrets })
    }
    fn read_sealed(&self, file: &str) -> Result<Document> {
        codec::unseal(&read_json(&self.directory.join(file))?)
    }
    pub fn save_config(&self, value: &Document) -> Result<()> {
        atomic_json(&self.directory.join("settings.json"), value, &|| {
            self.check_owner()
        })
    }
    pub fn save_config_scoped(
        &self,
        value: &Document,
        admission: &crate::PublicationScope<'_>,
    ) -> Result<()> {
        atomic_json_scoped(
            &self.directory.join("settings.json"),
            value,
            &|| self.check_owner(),
            admission,
        )
    }
    pub fn save_secrets(&self, value: &Document) -> Result<()> {
        self.save_secrets_scoped(value, &|publish| publish())
    }
    pub fn save_secrets_scoped(
        &self,
        value: &Document,
        admission: &PublicationScope<'_>,
    ) -> Result<()> {
        self.check_owner()?;
        atomic_json_scoped(
            &self.directory.join("vault.json"),
            &codec::seal(value)?,
            &|| self.check_owner(),
            admission,
        )
    }
    pub fn save_session(&self, value: &Document) -> Result<()> {
        self.check_owner()?;
        atomic_json(
            &self.directory.join("session.json"),
            &codec::seal(value)?,
            &|| self.check_owner(),
        )
    }
    pub fn read_session(&self) -> Result<Document> {
        self.read_sealed("session.json")
    }
    pub fn private_record_path(&self, key: &str) -> Result<PathBuf> {
        if key == "management-sessions" {
            return Ok(self.directory.join("management/sessions.json"));
        }
        let folder = if terminal(key) {
            "terminal"
        } else if onboarding(key) {
            "onboarding"
        } else {
            return Err(Error::invalid("Invalid private onboarding record."));
        };
        Ok(self.directory.join(folder).join(format!("{key}.json")))
    }
    pub fn read_private_record(&self, key: &str) -> Result<Option<Document>> {
        let file = self.private_record_path(key)?;
        let result = (|| {
            fs::parent_safe(file.parent().unwrap())?;
            let limit = if terminal(key) {
                1024 * 1024
            } else {
                256 * 1024
            };
            let mut file = fs::open_private(&file, limit)?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(limit + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > limit {
                return Err(Error::invalid("Unsafe private record."));
            }
            codec::unseal(&json(&bytes)?)
        })();
        match result {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.code == "ENOENT" => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub fn save_private_record(&self, key: &str, value: &Document) -> Result<()> {
        self.save_private_at(key, value, now_ms)
    }
    pub fn save_private_record_scoped(
        &self,
        key: &str,
        value: &Document,
        admission: &PublicationScope<'_>,
    ) -> Result<()> {
        self.save_private_scoped_at(key, value, now_ms, admission)
    }
    fn save_private_at(&self, key: &str, value: &Document, clock: impl Fn() -> f64) -> Result<()> {
        self.save_private_scoped_at(key, value, clock, &|publish| publish())
    }
    fn save_private_scoped_at(
        &self,
        key: &str,
        value: &Document,
        clock: impl Fn() -> f64,
        admission: &PublicationScope<'_>,
    ) -> Result<()> {
        self.check_owner()?;
        let file = self.private_record_path(key)?;
        let directory = file.parent().unwrap();
        fs::mkdir(directory)?;
        fs::parent_safe(directory)?;
        let is_terminal = terminal(key);
        if !is_terminal {
            let owned = std::fs::read_dir(directory)?
                .collect::<std::io::Result<Vec<_>>>()?
                .into_iter()
                .filter_map(|entry| match entry.file_type() {
                    Ok(kind)
                        if kind.is_file()
                            && entry
                                .file_name()
                                .to_str()
                                .and_then(|s| s.strip_suffix(".json"))
                                .is_some_and(onboarding) =>
                    {
                        Some(Ok(entry))
                    }
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                })
                .collect::<std::io::Result<Vec<_>>>()?;
            if owned.len() >= 64 {
                for entry in owned {
                    let target = entry.path();
                    let meta = std::fs::symlink_metadata(&target)?;
                    if target != file
                        && meta.is_file()
                        && fs::single_link(&target)?
                        && clock()
                            - meta
                                .modified()?
                                .duration_since(UNIX_EPOCH)
                                .map(|v| v.as_secs_f64() * 1000.0)
                                .unwrap_or(0.0)
                            > 48.0 * 3600000.0
                    {
                        self.check_owner()?;
                        std::fs::remove_file(target)?;
                    }
                }
            }
        }
        let count = std::fs::read_dir(directory)?
            .collect::<std::io::Result<Vec<_>>>()?
            .len();
        if count >= if is_terminal { 2048 } else { 128 }
            && !self
                .read_private_record(key)?
                .as_ref()
                .map(truthy)
                .transpose()?
                .unwrap_or(false)
        {
            return Err(Error::new("ECAPACITY", "Private record capacity reached."));
        }
        let raw = compact(value)?;
        if (is_terminal && raw.len() > 512 * 1024)
            || (!is_terminal && raw.encode_utf16().count() > 64 * 1024)
        {
            return Err(Error::new("ELIMIT", "Private record is too large."));
        }
        atomic_json_scoped(
            &file,
            &codec::seal(value)?,
            &|| self.check_owner(),
            admission,
        )
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod publication_tests {
    use super::*;
    #[test]
    fn generation_is_checked_at_rename_and_failed_publication_leaves_no_target() {
        let directory = std::env::temp_dir().join(format!(
            "c2l-store-guard-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = calls.clone();
        let store = Store::new(&directory).with_guard(std::sync::Arc::new(move || {
            if counter.fetch_add(1, Ordering::SeqCst) > 0 {
                Err(Error::new("EOWNER", "Stale generation"))
            } else {
                Ok(())
            }
        }));
        assert_eq!(
            store
                .save_config(&json(b"{\"changed\":true}").unwrap())
                .unwrap_err()
                .code,
            "EOWNER"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!directory.join("settings.json").exists());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        std::fs::remove_dir(directory).unwrap();
    }
}
