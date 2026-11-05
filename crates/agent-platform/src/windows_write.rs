//! Optimistic hash check followed by a handle-based NTFS rename, not filesystem CAS.
use super::{
    windows::{failure, info, open, root_handles, wide},
    windows_metadata::Metadata,
    windows_security::Descriptor,
};
use chat2local_protocol::{Failure, MAX_FILE_BYTES, Result, WriteRequest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*};
use windows_sys::{
    Wdk::Storage::FileSystem::{FileRenameInformationEx, NtSetInformationFile},
    Win32::System::IO::IO_STATUS_BLOCK,
};

fn io(_: std::io::Error) -> Failure {
    Failure::new("EIO", "Filesystem operation failed.")
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn busy() -> Failure {
    Failure::new(
        "EFENCE",
        "An unresolved write requires local inspection. Do not retry or roll back.",
    )
}
pub(super) fn handle(
    path: &Path,
    access: u32,
    share: u32,
    disposition: u32,
    security: Option<&Descriptor>,
) -> Result<File> {
    let attributes = security.map(Descriptor::attributes);
    let h = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            access,
            share,
            attributes.as_ref().map_or(null(), |v| v),
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(failure());
    }
    let f = unsafe { File::from_raw_handle(h) };
    if unsafe { GetFileType(h) } != FILE_TYPE_DISK
        || info(&f)?.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(Failure::new("ELINK", "Unsafe filesystem object."));
    }
    Ok(f)
}
fn regular(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let i = info(file)?;
    // Compression, encryption, sparse/offline data, reparse points and read-only
    // metadata need a separate preservation contract and are deliberately refused.
    if i.nNumberOfLinks != 1
        || i.dwFileAttributes & !(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE) != 0
        || ((i.nFileSizeHigh as u64) << 32 | i.nFileSizeLow as u64) > MAX_FILE_BYTES
    {
        return Err(Failure::new(
            "EFILE",
            "Only ordinary single-link writable text files are supported.",
        ));
    }
    Ok(i)
}
fn bytes(file: &mut File) -> Result<Vec<u8>> {
    regular(file)?;
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut b = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut b)
        .map_err(io)?;
    if b.len() as u64 > MAX_FILE_BYTES || b.contains(&0) {
        return Err(Failure::new(
            "EFILE",
            "Only UTF-8 text up to 64 KiB is supported.",
        ));
    }
    std::str::from_utf8(&b).map_err(|_| Failure::new("EILSEQ", "Invalid UTF-8 text."))?;
    Ok(b)
}
pub(super) fn ntfs(file: &File) -> Result<()> {
    let mut name = [0u16; 32];
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } == 0
    {
        return Err(failure());
    }
    if String::from_utf16_lossy(&name[..name.iter().position(|c| *c == 0).unwrap_or(name.len())])
        != "NTFS"
    {
        return Err(Failure::new("ENOTSUP", "Rust writing requires local NTFS."));
    }
    Ok(())
}
pub(super) fn no_streams(path: &Path) -> Result<()> {
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { zeroed() };
    let h = unsafe {
        FindFirstStreamW(
            wide(path).as_ptr(),
            FindStreamInfoStandard,
            (&mut data as *mut WIN32_FIND_STREAM_DATA).cast(),
            0,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(failure());
    }
    let first = String::from_utf16_lossy(
        &data.cStreamName[..data
            .cStreamName
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(data.cStreamName.len())],
    );
    let extra = unsafe { FindNextStreamW(h, (&mut data as *mut WIN32_FIND_STREAM_DATA).cast()) };
    let end = unsafe { GetLastError() };
    unsafe {
        FindClose(h);
    }
    if first != "::$DATA" || extra != 0 || end != ERROR_HANDLE_EOF {
        return Err(Failure::new(
            "ENOTSUP",
            "Alternate file streams are unsupported.",
        ));
    }
    Ok(())
}
pub(super) fn delete_handle(file: &File) {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        );
    }
}
fn record(file: &mut File, value: &Value) -> Result<()> {
    let data = serde_json::to_vec(value).map_err(|_| busy())?;
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    file.write_all(&data).map_err(io)?;
    file.set_len(data.len() as u64).map_err(io)?;
    file.sync_all().map_err(io)
}
fn checked_records(directory: &Path, private: &Descriptor) -> Result<()> {
    for entry in std::fs::read_dir(directory).map_err(io)? {
        let entry = entry.map_err(io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(busy)?;
        if name == "writer.lock" || name.ends_with(".before") {
            continue;
        }
        if !name.ends_with(".json") {
            return Err(busy());
        }
        let mut f = handle(
            &entry.path(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            None,
        )?;
        private.matches(&f, false)?;
        regular(&f)?;
        let mut data = Vec::new();
        (&mut f).take(16385).read_to_end(&mut data).map_err(io)?;
        let v: Value = serde_json::from_slice(&data).map_err(|_| busy())?;
        if data.len() > 16384 || !valid_completed(&v, name) {
            return Err(busy());
        }
    }
    Ok(())
}
fn valid_completed(v: &Value, name: &str) -> bool {
    v.as_object().is_some_and(|o| o.len() == 6)
        && v["v"] == 1
        && v["operationId"]
            .as_str()
            .is_some_and(|id| name == format!("{id}.json"))
        && v["intent"]
            .as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
        && ["complete", "aborted"].contains(&v["phase"].as_str().unwrap_or(""))
        && v["sha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
        && valid_binding(&v["binding"])
}
fn valid_binding(v: &Value) -> bool {
    let nullable = |v: &Value, n: usize| {
        v.is_null()
            || v.as_str()
                .is_some_and(|s| s.len() == n && s.bytes().all(|c| c.is_ascii_hexdigit()))
    };
    v.as_object().is_some_and(|o| {
        o.len() == 8
            && [
                "rootId",
                "rootPath",
                "path",
                "beforeHash",
                "deviceId",
                "resource",
                "connectionId",
                "fileId",
            ]
            .iter()
            .all(|k| o.contains_key(*k))
    }) && v["rootId"].as_str().is_some_and(|s| {
        !s.is_empty()
            && s.len() <= 80
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    }) && v["rootPath"].as_str().is_some_and(|s| !s.is_empty())
        && v["path"]
            .as_str()
            .is_some_and(|s| chat2local_policy::relative_parts(s, false).is_ok())
        && nullable(&v["beforeHash"], 64)
        && nullable(&v["deviceId"], 32)
        && nullable(&v["connectionId"], 32)
        && (v["resource"].is_null() || v["resource"].as_str().is_some_and(|s| s.len() <= 2048))
        && (v["fileId"].is_null()
            || v["fileId"].as_array().is_some_and(|a| {
                a.len() == 3
                    && a.iter()
                        .all(|n| n.as_u64().is_some_and(|n| n <= u32::MAX as u64))
            }))
}

pub struct PreparedWrite {
    guard: crate::PublicationGuard,
    // Handles live through Drop, including all handle-based cleanup.
    _guards: Vec<File>,
    _lock: File,
    target_path: PathBuf,
    target: Option<File>,
    identity: Option<(u32, u32, u32)>,
    expected: Option<String>,
    security: Option<Descriptor>,
    metadata: Option<Metadata>,
    staged_security: Option<Descriptor>,
    staged_metadata: Option<Metadata>,
    temporary_path: PathBuf,
    temporary: Option<File>,
    fence: Option<File>,
    record: Value,
    attempted: bool,
    backup_saved: bool,
    #[cfg(test)]
    fail_after_rename: bool,
}
impl Drop for PreparedWrite {
    fn drop(&mut self) {
        // An ambiguous native return could already have published this handle.
        // Never delete it after a commit attempt, even when rename reported error.
        if (self.guard)().is_ok()
            && !self.attempted
            && let Some(temp) = &self.temporary
        {
            delete_handle(temp);
        }
        if (self.guard)().is_ok()
            && !self.attempted
            && let Some(fence) = &mut self.fence
        {
            self.record["phase"] = json!("aborted");
            // A failure deliberately leaves an invalid/unresolved fence.
            let _ = record(fence, &self.record);
        }
    }
}

impl PreparedWrite {
    pub fn prepare(write: &WriteRequest, intent: &str) -> Result<Self> {
        Self::prepare_guarded(write, intent, std::sync::Arc::new(|| Ok(())))
    }
    pub fn prepare_guarded(
        write: &WriteRequest,
        intent: &str,
        guard: crate::PublicationGuard,
    ) -> Result<Self> {
        guard()?;
        let parts = chat2local_policy::authorize_write(write)?;
        let (mut target_path, mut guards) = root_handles(&write.request.authority.root.path)?;
        ntfs(guards.last().ok_or_else(busy)?)?;
        for (i, part) in parts.iter().enumerate() {
            target_path.push(part);
            if i + 1 < parts.len() {
                guards.push(open(&target_path, true)?);
            }
        }
        let mut target = match handle(
            &target_path,
            FILE_GENERIC_READ | FILE_WRITE_DATA,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            None,
        ) {
            Ok(f) => Some(f),
            Err(e) if e.code == "ENOENT" && write.expected_hash.is_none() => None,
            Err(e) => return Err(e),
        };
        let original = target.as_mut().map(bytes).transpose()?;
        if original.as_ref().map(|b| hash(b)) != write.expected_hash {
            return Err(Failure::new(
                "ECONFLICT",
                "File changed; nothing was written.",
            ));
        }
        let identity = target
            .as_ref()
            .map(info)
            .transpose()?
            .map(|i| (i.dwVolumeSerialNumber, i.nFileIndexHigh, i.nFileIndexLow));
        let security = target.as_ref().map(Descriptor::read).transpose()?;
        let metadata = target.as_ref().map(Metadata::read).transpose()?;
        if target.is_some() {
            no_streams(&target_path)?;
        }
        let (state, state_guards) = root_handles(&write.state_dir)?;
        ntfs(state_guards.last().ok_or_else(busy)?)?;
        guards.extend(state_guards);
        let private = Descriptor::private()?;
        let directory = state.join("rust-writes");
        guard()?;
        let attributes = private.attributes();
        if unsafe { CreateDirectoryW(wide(&directory).as_ptr(), &attributes) } == 0
            && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
        {
            return Err(failure());
        }
        let directory_guard = handle(
            &directory,
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            None,
        )?;
        if info(&directory_guard)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(busy());
        }
        private.matches(&directory_guard, false)?;
        guards.push(directory_guard);
        guard()?;
        let lock = handle(
            &directory.join("writer.lock"),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            OPEN_ALWAYS,
            Some(&private),
        )?;
        private.matches(&lock, false)?;
        regular(&lock)?;
        checked_records(&directory, &private)?;
        let mut prepared = Self {
            guard,
            _guards: guards,
            _lock: lock,
            target_path,
            target,
            identity,
            expected: write.expected_hash.clone(),
            security,
            metadata,
            staged_security: None,
            staged_metadata: None,
            temporary_path: PathBuf::new(),
            temporary: None,
            fence: None,
            record: json!({"v":1,"operationId":write.operation_id,"intent":intent,"phase":"prepared","sha256":hash(write.content.as_bytes()),
                "binding":{"rootId":write.request.args.root_id,"rootPath":write.request.authority.root.path,"path":write.request.args.path,"beforeHash":write.expected_hash,
                    "deviceId":write.request.authority.device_id,"resource":write.request.authority.resource,
                    "connectionId":write.request.authority.access.as_ref().map(|a| &a.connection_id),"fileId":identity}}),
            attempted: false,
            backup_saved: false,
            #[cfg(test)]
            fail_after_rename: false,
        };
        (prepared.guard)()?;
        let fence = handle(
            &directory.join(format!("{}.json", write.operation_id)),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
            CREATE_NEW,
            Some(&private),
        )?;
        private.matches(&fence, false)?;
        prepared.fence = Some(fence);
        (prepared.guard)()?;
        record(prepared.fence.as_mut().ok_or_else(busy)?, &prepared.record)?;
        if let Some(original) = original {
            (prepared.guard)()?;
            let mut backup = handle(
                &directory.join(format!("{}.before", write.operation_id)),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ,
                CREATE_NEW,
                Some(&private),
            )?;
            private.matches(&backup, false)?;
            (prepared.guard)()?;
            backup.write_all(&original).map_err(io)?;
            backup.sync_all().map_err(io)?;
            prepared.backup_saved = true;
        }
        let temp_path = prepared
            .target_path
            .with_file_name(format!(".chat2local-{}.tmp", write.operation_id));
        prepared.temporary_path = temp_path.clone();
        (prepared.guard)()?;
        let temp = handle(
            &temp_path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ,
            CREATE_NEW,
            Some(&private),
        )?;
        prepared.temporary = Some(temp);
        let temp = prepared.temporary.as_mut().ok_or_else(busy)?;
        private.matches(temp, false)?;
        (prepared.guard)()?;
        if let Some(security) = &prepared.security {
            security.apply(temp)?;
        }
        if let Some(metadata) = &prepared.metadata {
            metadata.matches(temp)?;
        }
        // Security is installed and verified before any body is placed in temp.
        (prepared.guard)()?;
        temp.write_all(write.content.as_bytes()).map_err(io)?;
        temp.sync_all().map_err(io)?;
        if let Some(target) = &prepared.target {
            let mut basic: FILE_BASIC_INFO = unsafe { zeroed() };
            if unsafe {
                GetFileInformationByHandleEx(
                    target.as_raw_handle(),
                    FileBasicInfo,
                    (&mut basic as *mut FILE_BASIC_INFO).cast(),
                    size_of::<FILE_BASIC_INFO>() as u32,
                )
            } == 0
            {
                return Err(failure());
            }
            basic.LastAccessTime = 0;
            basic.LastWriteTime = 0;
            basic.ChangeTime = 0;
            if unsafe {
                SetFileInformationByHandle(
                    temp.as_raw_handle(),
                    FileBasicInfo,
                    (&basic as *const FILE_BASIC_INFO).cast(),
                    size_of::<FILE_BASIC_INFO>() as u32,
                )
            } == 0
            {
                return Err(failure());
            }
        }
        prepared.staged_security = Some(Descriptor::read(temp)?);
        prepared.staged_metadata = Some(Metadata::read(temp)?);
        Ok(prepared)
    }

    pub fn commit(&mut self) -> Result<Value> {
        self.commit_admitted(|submit| submit())
    }
    pub fn commit_admitted(
        &mut self,
        admit: impl FnOnce(&mut dyn FnMut() -> Result<()>) -> Result<()>,
    ) -> Result<Value> {
        (self.guard)()?;
        if self.attempted {
            return Err(busy());
        }
        let temp = self.temporary.as_mut().ok_or_else(busy)?;
        if hash(&bytes(temp)?) != self.record["sha256"].as_str().ok_or_else(busy)? {
            return Err(Failure::new(
                "ECONFLICT",
                "Staged bytes changed; nothing was written.",
            ));
        }
        self.staged_security
            .as_ref()
            .ok_or_else(busy)?
            .matches(temp, true)?;
        self.staged_metadata
            .as_ref()
            .ok_or_else(busy)?
            .matches(temp)?;
        no_streams(&self.temporary_path)?;
        if let Some(expected) = &self.expected {
            let mut current = handle(
                &self.target_path,
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                OPEN_EXISTING,
                None,
            )?;
            let i = regular(&current)?;
            if Some((i.dwVolumeSerialNumber, i.nFileIndexHigh, i.nFileIndexLow)) != self.identity
                || hash(&bytes(&mut current)?) != *expected
            {
                return Err(Failure::new(
                    "ECONFLICT",
                    "Concurrent file change; nothing was written.",
                ));
            }
            self.security
                .as_ref()
                .ok_or_else(busy)?
                .matches(&current, true)?;
            self.metadata.as_ref().ok_or_else(busy)?.matches(&current)?;
            no_streams(&self.target_path)?;
        }
        (self.guard)()?;
        self.record["phase"] = json!("committing");
        record(self.fence.as_mut().ok_or_else(busy)?, &self.record)?;
        let attempt = || -> Result<()> {
            (self.guard)()?;
            let temp = self.temporary.as_ref().ok_or_else(busy)?;
            let name: Vec<u16> = self
                .target_path
                .file_name()
                .ok_or_else(busy)?
                .encode_wide()
                .collect();
            let length = size_of::<FILE_RENAME_INFO>() + name.len() * 2;
            let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
            let rename = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
            unsafe {
                (*rename).Anonymous.Flags = if self.expected.is_some() { 3 } else { 0 };
                (*rename).RootDirectory = null_mut();
                (*rename).FileNameLength = (name.len() * 2) as u32;
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    (*rename).FileName.as_mut_ptr(),
                    name.len(),
                );
                // The Win32 wrapper reopens the parent and conflicts with our
                // deny-write directory guard. The documented user-mode NT API
                // resolves a basename with NULL RootDirectory in the source file's
                // existing directory. Temp and target are in that same held directory.
                // Class 65 performs normal access checks; never use bypass class 66.
                let mut status: IO_STATUS_BLOCK = zeroed();
                let mut submit = || {
                    self.attempted = true;
                    let result = NtSetInformationFile(
                        temp.as_raw_handle(),
                        &mut status,
                        rename.cast(),
                        length as u32,
                        FileRenameInformationEx,
                    );
                    if result != 0 {
                        #[cfg(test)]
                        eprintln!("native rename NTSTATUS: {result:#x}");
                        return Err(Failure::new("EIO", "Native rename failed."));
                    }
                    Ok(())
                };
                admit(&mut submit)?;
            }
            Ok(())
        };
        if let Err(error) = attempt() {
            return Err(if self.attempted {
                Failure::new(
                    "EUNKNOWN",
                    "Write outcome is unknown; inspect locally before proceeding.",
                )
            } else {
                error
            });
        }
        #[cfg(test)]
        if self.fail_after_rename {
            return Err(Failure::new("EUNKNOWN", "Injected completion failure."));
        }
        self.temporary
            .as_ref()
            .ok_or_else(busy)?
            .sync_all()
            .map_err(|_| Failure::new("EUNKNOWN", "Write outcome is unknown."))?;
        if let Some(metadata) = &self.metadata {
            metadata
                .matches(self.temporary.as_ref().ok_or_else(busy)?)
                .map_err(|_| Failure::new("EUNKNOWN", "Write security outcome is unknown."))?;
        }
        (self.guard)()
            .map_err(|_| Failure::new("EUNKNOWN", "Write owner changed after admission."))?;
        self.record["phase"] = json!("complete");
        record(self.fence.as_mut().ok_or_else(busy)?, &self.record)
            .map_err(|_| Failure::new("EUNKNOWN", "Write outcome is unknown."))?;
        Ok(json!({"sha256":self.record["sha256"],"backupSaved":self.backup_saved}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn fixture() -> (Fixture, WriteRequest) {
        let base = std::env::temp_dir().join(format!(
            "c2l-write-native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&base).unwrap();
        let project = base.join("project");
        let state = base.join("state");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&state).unwrap();
        let write: WriteRequest = serde_json::from_value(json!({
            "request":{"v":1,"id":"11111111-1111-1111-1111-111111111111","op":"read_file","args":{"rootId":"root","path":"file.txt"},
            "authority":{"paused":false,"deviceId":null,"resource":null,"access":null,"root":{"id":"root","path":project,"kind":"legacy","connectionId":null,"writeMode":"direct"}}},
            "operationId":"22222222-2222-2222-2222-222222222222","authorization":"directory-direct","expectedHash":null,"content":"hello","stateDir":state
        })).unwrap();
        (Fixture(base), write)
    }
    #[test]
    fn native_create_replace_guards_acl_and_lock() {
        let (fixture, mut write) = fixture();
        let target = fixture.0.join("project").join("file.txt");
        let mut prepared = PreparedWrite::prepare(&write, &"a".repeat(64)).unwrap();
        assert!(std::fs::rename(fixture.0.join("project"), fixture.0.join("moved")).is_err());
        assert!(PreparedWrite::prepare(&write, &"b".repeat(64)).is_err());
        assert!(prepared.commit().is_ok());
        drop(prepared);
        let existing = open(&target, false).unwrap();
        let security = Descriptor::read(&existing).unwrap();
        drop(existing);
        write.operation_id = "33333333-3333-3333-3333-333333333333".to_owned();
        write.expected_hash = Some(hash(b"hello"));
        write.content = "replacement".to_owned();
        let mut prepared = PreparedWrite::prepare(&write, &"c".repeat(64)).unwrap();
        assert!(std::fs::write(&target, "intruder").is_err());
        assert!(prepared.commit().is_ok());
        drop(prepared);
        assert_eq!(std::fs::read(&target).unwrap(), b"replacement");
        security
            .matches(&open(&target, false).unwrap(), true)
            .unwrap();
    }
    #[test]
    fn completion_failure_keeps_published_file_and_blocks_next_writer() {
        let (fixture, mut write) = fixture();
        let mut prepared = PreparedWrite::prepare(&write, &"a".repeat(64)).unwrap();
        prepared.fail_after_rename = true;
        assert_eq!(prepared.commit().unwrap_err().code, "EUNKNOWN");
        drop(prepared);
        assert_eq!(
            std::fs::read(fixture.0.join("project/file.txt")).unwrap(),
            b"hello"
        );
        write.expected_hash = Some(hash(b"hello"));
        assert!(matches!(
            PreparedWrite::prepare(&write, &"b".repeat(64)),
            Err(Failure { code: "EFENCE", .. })
        ));
    }
    #[test]
    fn exclusive_create_collision_keeps_original_and_staging_evidence() {
        let (fixture, write) = fixture();
        let mut prepared = PreparedWrite::prepare(&write, &"a".repeat(64)).unwrap();
        let target = fixture.0.join("project/file.txt");
        std::fs::write(&target, "competitor").unwrap();
        assert_eq!(prepared.commit().unwrap_err().code, "EUNKNOWN");
        drop(prepared);
        assert_eq!(std::fs::read(&target).unwrap(), b"competitor");
        assert!(
            fixture
                .0
                .join("project/.chat2local-22222222-2222-2222-2222-222222222222.tmp")
                .exists()
        );
    }
}
