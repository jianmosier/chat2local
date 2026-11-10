use crate::value;
use chat2local_native_store::{Error, Result, Store};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

fn generation(directory: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(directory.join("session.json")) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
pub struct Ownership {
    directory: PathBuf,
    expected: Mutex<Option<Vec<u8>>>,
    #[cfg(windows)]
    _prior: Option<chat2local_agent_platform::ProcessOwner>,
}
fn refuse() -> Error {
    Error::new(
        "EOWNER",
        "Previous controller ownership is live, uncertain, or changed.",
    )
}
pub(crate) enum Metadata {
    Legacy,
    Native { created: String, image: String },
}
pub(crate) fn metadata(session: &chat2local_js_value_compat::Document) -> Result<Metadata> {
    let created = value::prop(session, "ownerCreated");
    let image = value::prop(session, "ownerImage");
    match (created, image) {
        (None, None) => Ok(Metadata::Legacy),
        (Some(_), Some(_)) => {
            let created = value::string(session, created)
                .filter(|v| v.parse::<u64>().is_ok_and(|n| n > 0 && n.to_string() == *v))
                .ok_or_else(refuse)?;
            let image = value::string(session, image)
                .filter(|v| Path::new(v).is_absolute() && !v.chars().any(char::is_control))
                .ok_or_else(refuse)?;
            Ok(Metadata::Native { created, image })
        }
        _ => Err(refuse()),
    }
}
struct Observed<T> {
    handle: T,
    exited: bool,
    created: String,
    image: std::result::Result<String, i32>,
}
fn classify(
    metadata: &Metadata,
    exited: bool,
    created: &str,
    image: &std::result::Result<String, i32>,
) -> Result<bool> {
    // A signaled process handle identifies an exited kernel object. Keeping it
    // prevents PID reuse. Error 31 is accepted only for that dead object, after
    // GetProcessTimes succeeded and any saved creation identity matched.
    match metadata {
        Metadata::Native {
            created: expected,
            image: expected_image,
        } => {
            if expected != created {
                return Err(refuse());
            }
            match image {
                Ok(actual) if actual == expected_image => Ok(exited),
                Err(31) if exited => Ok(true),
                _ => Err(refuse()),
            }
        }
        Metadata::Legacy if exited && (image.is_ok() || matches!(image, Err(31))) => Ok(true),
        Metadata::Legacy => Err(refuse()),
    }
}
#[cfg(windows)]
pub(crate) fn dead(
    metadata: &Metadata,
    probe: &chat2local_agent_platform::ProcessProbe,
) -> Result<bool> {
    classify(metadata, probe.exited, &probe.created, &probe.image)
}
fn inspect_prior<T>(
    metadata: &Metadata,
    mut unchanged: impl FnMut() -> Result<()>,
    mut probe: impl FnMut() -> Result<Option<Observed<T>>>,
) -> Result<Option<T>> {
    unchanged()?;
    let observed = probe()?;
    unchanged()?;
    let Some(observed) = observed else {
        return Ok(None);
    };
    if !classify(
        metadata,
        observed.exited,
        &observed.created,
        &observed.image,
    )? {
        return Err(refuse());
    }
    Ok(Some(observed.handle))
}
impl Ownership {
    pub fn claim(directory: &Path) -> Result<Arc<Self>> {
        let expected = generation(directory)?;
        #[cfg(windows)]
        let mut prior = None;
        if expected.is_some() {
            let session = Store::new(directory).read_session()?;
            let pid = value::number(&session, value::prop(&session, "pid"))
                .filter(|p| p.fract() == 0.0 && *p > 0.0 && *p <= u32::MAX as f64)
                .ok_or_else(refuse)? as u32;
            if value::string(&session, value::prop(&session, "instanceId")).is_none() {
                return Err(refuse());
            }
            #[cfg(windows)]
            {
                let metadata = metadata(&session)?;
                prior = inspect_prior(
                    &metadata,
                    || {
                        if generation(directory)? == expected {
                            Ok(())
                        } else {
                            Err(refuse())
                        }
                    },
                    || {
                        let Some(handle) = chat2local_agent_platform::ProcessOwner::open(pid)
                            .map_err(|_| refuse())?
                        else {
                            return Ok(None);
                        };
                        let actual = handle.probe().map_err(|_| refuse())?;
                        Ok(Some(Observed {
                            handle,
                            exited: actual.exited,
                            created: actual.created,
                            image: actual.image,
                        }))
                    },
                )?;
            }
            #[cfg(not(windows))]
            {
                let _ = pid;
                return Err(Error::new(
                    "ENOTSUP",
                    "Native owner inspection requires Windows.",
                ));
            }
        }
        if generation(directory)? != expected {
            return Err(refuse());
        }
        Ok(Arc::new(Self {
            directory: directory.to_owned(),
            expected: Mutex::new(expected),
            #[cfg(windows)]
            _prior: prior,
        }))
    }
    pub fn check(&self) -> Result<()> {
        if generation(&self.directory)? != *self.expected.lock().map_err(|_| refuse())? {
            return Err(refuse());
        }
        Ok(())
    }
    pub fn published(&self, instance: &str) -> Result<()> {
        let now = generation(&self.directory)?.ok_or_else(refuse)?;
        let session = Store::new(&self.directory).read_session()?;
        if value::string(&session, value::prop(&session, "instanceId")).as_deref() != Some(instance)
            || generation(&self.directory)?.as_ref() != Some(&now)
        {
            return Err(refuse());
        }
        *self.expected.lock().map_err(|_| refuse())? = Some(now);
        Ok(())
    }
    pub fn store(self: &Arc<Self>) -> Store {
        let owner = self.clone();
        Store::new(&self.directory).with_guard(Arc::new(move || owner.check()))
    }
    pub fn identity() -> Result<(String, String)> {
        #[cfg(windows)]
        {
            chat2local_agent_platform::ProcessOwner::open(std::process::id())?
                .ok_or_else(refuse)?
                .identity()
                .map_err(Into::into)
        }
        #[cfg(not(windows))]
        {
            Err(Error::new(
                "ENOTSUP",
                "Native owner inspection requires Windows.",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    fn native() -> Metadata {
        Metadata::Native {
            created: "42".into(),
            image: r"C:\native.exe".into(),
        }
    }
    #[test]
    fn malformed_or_half_metadata_never_becomes_legacy_even_for_absent_pid() {
        assert!(matches!(
            metadata(&value::parse(b"{}").unwrap()).unwrap(),
            Metadata::Legacy
        ));
        for input in [
            r#"{"ownerCreated":42}"#,
            r#"{"ownerImage":null}"#,
            r#"{"ownerCreated":"42"}"#,
            r#"{"ownerImage":"C:\\native.exe"}"#,
            r#"{"ownerCreated":"0","ownerImage":"C:\\native.exe"}"#,
            r#"{"ownerCreated":"42","ownerImage":"relative"}"#,
            r#"{"ownerCreated":"42","ownerImage":"\ud800"}"#,
        ] {
            assert!(metadata(&value::parse(input.as_bytes()).unwrap()).is_err());
        }
        assert!(
            metadata(
                &value::parse(br#"{"ownerCreated":"42","ownerImage":"C:\\native.exe"}"#).unwrap()
            )
            .is_ok()
        );
    }
    #[test]
    fn dead_classification_keeps_creation_and_readable_image_checks() {
        for meta in [Metadata::Legacy, native()] {
            assert!(classify(&meta, true, "42", &Err(31)).unwrap());
            assert!(classify(&meta, true, "42", &Ok(r"C:\native.exe".into())).unwrap());
            assert!(classify(&meta, false, "42", &Err(31)).is_err());
            assert!(classify(&meta, true, "42", &Err(5)).is_err());
        }
        assert!(classify(&native(), true, "43", &Err(31)).is_err());
        assert!(classify(&native(), true, "42", &Ok(r"C:\other.exe".into())).is_err());
        assert!(!classify(&native(), false, "42", &Ok(r"C:\native.exe".into())).unwrap());
        assert!(classify(&Metadata::Legacy, false, "42", &Ok(r"C:\native.exe".into())).is_err());
    }
    #[test]
    fn generation_before_and_after_probe_and_failed_queries_refuse() {
        for change_at in [1, 2] {
            let checks = Cell::new(0);
            let probes = Cell::new(0);
            assert!(
                inspect_prior::<()>(
                    &native(),
                    || {
                        checks.set(checks.get() + 1);
                        if checks.get() == change_at {
                            Err(refuse())
                        } else {
                            Ok(())
                        }
                    },
                    || {
                        probes.set(probes.get() + 1);
                        Ok(None)
                    }
                )
                .is_err()
            );
            assert_eq!(probes.get(), usize::from(change_at > 1));
        }
        assert!(inspect_prior::<()>(&native(), || Ok(()), || Err(refuse())).is_err());
    }
    #[test]
    fn accepted_dead_handle_remains_owned_until_owner_release() {
        struct Handle<'a>(&'a Cell<bool>);
        impl Drop for Handle<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let dropped = Cell::new(false);
        let held = inspect_prior(
            &native(),
            || Ok(()),
            || {
                Ok(Some(Observed {
                    handle: Handle(&dropped),
                    exited: true,
                    created: "42".into(),
                    image: Err(31),
                }))
            },
        )
        .unwrap();
        assert!(!dropped.get());
        drop(held);
        assert!(dropped.get());
    }
    #[test]
    fn child_for_held_dead_process() {
        if std::env::var_os("CHAT2LOCAL_OWNED_PROCESS_PROBE_CHILD").is_some() {
            use std::io::Read;
            let mut input = [0];
            std::io::stdin().read_exact(&mut input).unwrap();
        }
    }
    #[cfg(windows)]
    #[test]
    fn actual_dead_process_with_external_handle_allows_native_and_legacy_claim() {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "owner::tests::child_for_held_dead_process",
                "--nocapture",
            ])
            .env("CHAT2LOCAL_OWNED_PROCESS_PROBE_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let external = chat2local_agent_platform::ProcessOwner::open(child.id())
            .unwrap()
            .unwrap();
        let (created, image) = external.identity().unwrap();
        child.stdin.take().unwrap().write_all(&[0]).unwrap();
        assert!(child.wait().unwrap().success());
        assert!(external.exited().unwrap());
        for legacy in [false, true] {
            let directory =
                std::env::temp_dir().join(format!("c2l-owned-dead-{}", crate::random(8).unwrap()));
            std::fs::create_dir(&directory).unwrap();
            let store = Store::new(&directory);
            let mut session = serde_json::json!({"pid":child.id(),"instanceId":"owned-exit-probe"});
            if !legacy {
                session["ownerCreated"] = serde_json::json!(created);
                session["ownerImage"] = serde_json::json!(image);
            }
            store
                .save_session(&value::parse(session.to_string().as_bytes()).unwrap())
                .unwrap();
            let owner = Ownership::claim(&directory).unwrap();
            assert!(owner._prior.as_ref().unwrap().exited().unwrap());
            owner.check().unwrap();
            drop(owner);
            std::fs::remove_dir_all(directory).unwrap();
        }
        assert!(external.exited().unwrap());
    }
}
