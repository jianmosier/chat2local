//! Current-user DPAPI terminal journal. No persistent lock, retries or launch API.
use super::{
    windows::{failure, info, root_handles, wide},
    windows_metadata::Metadata,
    windows_security::Descriptor,
    windows_write::{delete_handle, handle, no_streams, ntfs},
};
use chat2local_protocol::{Failure, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::{size_of, zeroed},
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::Path,
    ptr::null_mut,
};
use windows_sys::{
    Wdk::Storage::FileSystem::{FileRenameInformationEx, NtSetInformationFile},
    Win32::{
        Foundation::*,
        Security::Cryptography::*,
        Storage::FileSystem::*,
        System::{IO::IO_STATUS_BLOCK, Threading::*},
    },
};
const PLAIN: usize = 512 * 1024;
const ENCRYPTED: usize = 1024 * 1024;
fn invalid() -> Failure {
    Failure::new(
        "EJOURNAL",
        "Terminal journal is invalid; no command may be replayed.",
    )
}
fn io(_: std::io::Error) -> Failure {
    Failure::new("EIO", "Terminal journal operation failed.")
}
fn unknown() -> Failure {
    Failure::new(
        "EUNKNOWN",
        "Journal outcome unknown. No launch right was granted; do not replay.",
    )
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Record {
    request_id: String,
    root_id: String,
    connection_id: String,
    resource: String,
    device_id: String,
    input_hash: String,
    status: String,
}
fn record(raw: &str, id: &str) -> Result<Record> {
    if raw.len() > PLAIN {
        return Err(Failure::new("ESIZE", "Terminal record exceeds 512 KiB."));
    }
    // Unknown JSON fields stay in the original text, including escaped UTF-16.
    // The ignored-field parser never canonicalizes them or recalculates a hash.
    let value: Record = serde_json::from_str(raw).map_err(|_| invalid())?;
    if value.request_id != id
        || !uuid(id)
        || !hex(&value.input_hash, 64)
        || !hex(&value.connection_id, 32)
        || !hex(&value.device_id, 32)
        || value.root_id.is_empty()
        || value.root_id.len() > 80
        || !value
            .root_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        || value.resource.is_empty()
        || value.resource.len() > 2048
        || !matches!(
            value.status.as_str(),
            "starting"
                | "running"
                | "stopping"
                | "succeeded"
                | "failed"
                | "cancelled"
                | "timed-out"
                | "interrupted"
        )
    {
        return Err(invalid());
    }
    Ok(value)
}
fn same_owner(a: &Record, b: &Record) -> bool {
    a.request_id == b.request_id
        && a.root_id == b.root_id
        && a.connection_id == b.connection_id
        && a.resource == b.resource
        && a.device_id == b.device_id
        && a.input_hash == b.input_hash
}
fn rank(status: &str) -> u8 {
    match status {
        "starting" => 0,
        "running" => 1,
        "stopping" => 2,
        _ => 3,
    }
}
fn regular(file: &File) -> Result<()> {
    let metadata = info(file)?;
    if metadata.nNumberOfLinks != 1
        || metadata.dwFileAttributes & !(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE) != 0
        || ((metadata.nFileSizeHigh as u64) << 32 | metadata.nFileSizeLow as u64) > ENCRYPTED as u64
    {
        return Err(invalid());
    }
    Ok(())
}
fn bytes(file: &mut File) -> Result<Vec<u8>> {
    regular(file)?;
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut result = Vec::new();
    file.take(ENCRYPTED as u64 + 1)
        .read_to_end(&mut result)
        .map_err(io)?;
    if result.len() > ENCRYPTED {
        return Err(invalid());
    }
    Ok(result)
}
fn dpapi(input: &[u8], protect: bool) -> Result<Vec<u8>> {
    super::windows_dpapi::current_user_data(input, protect, ENCRYPTED)
}
fn encode(input: &[u8]) -> Result<String> {
    let mut size = 0;
    if unsafe {
        CryptBinaryToStringA(
            input.as_ptr(),
            input.len() as u32,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            null_mut(),
            &mut size,
        )
    } == 0
    {
        return Err(invalid());
    }
    let mut output = vec![0u8; size as usize];
    if unsafe {
        CryptBinaryToStringA(
            input.as_ptr(),
            input.len() as u32,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            output.as_mut_ptr(),
            &mut size,
        )
    } == 0
    {
        return Err(invalid());
    }
    output.truncate(size as usize);
    if output.last() == Some(&0) {
        output.pop();
    }
    String::from_utf8(output).map_err(|_| invalid())
}
fn decode(input: &str) -> Result<Vec<u8>> {
    if input.is_empty() || input.len() > ENCRYPTED {
        return Err(invalid());
    }
    let mut size = 0;
    if unsafe {
        CryptStringToBinaryA(
            input.as_ptr(),
            input.len() as u32,
            CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
            null_mut(),
            &mut size,
            null_mut(),
            null_mut(),
        )
    } == 0
    {
        return Err(invalid());
    }
    let mut output = vec![0u8; size as usize];
    if unsafe {
        CryptStringToBinaryA(
            input.as_ptr(),
            input.len() as u32,
            CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
            output.as_mut_ptr(),
            &mut size,
            null_mut(),
            null_mut(),
        )
    } == 0
    {
        return Err(invalid());
    }
    output.truncate(size as usize);
    if encode(&output)? != input {
        return Err(invalid());
    }
    Ok(output)
}
fn unseal(input: &[u8], id: &str) -> Result<String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        format: String,
        data: String,
    }
    let envelope: Envelope = serde_json::from_slice(input).map_err(|_| invalid())?;
    if envelope.format != "windows-dpapi-v1" {
        return Err(invalid());
    }
    let plaintext = dpapi(&decode(&envelope.data)?, false)?;
    let raw = String::from_utf8(plaintext).map_err(|_| invalid())?;
    record(&raw, id)?;
    Ok(raw)
}
struct Mutex(HANDLE);
impl Drop for Mutex {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
impl Mutex {
    fn lock(directory: &File) -> Result<Self> {
        let mutex_security = Descriptor::private_mutex()?;
        let i = info(directory)?;
        let name: Vec<u16> = format!(
            "Global\\Chat2Local.Terminal.{:08x}.{:08x}{:08x}",
            i.dwVolumeSerialNumber, i.nFileIndexHigh, i.nFileIndexLow
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let handle = unsafe { CreateMutexW(&mutex_security.attributes(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(failure());
        }
        if let Err(error) = mutex_security.matches_mutex(handle) {
            unsafe {
                CloseHandle(handle);
            }
            return Err(error);
        }
        // An abandoned owner grants the lock only, never a launch right. All
        // records are reopened and checked under the lock before every action.
        match unsafe { WaitForSingleObject(handle, 5000) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(handle)),
            _ => {
                unsafe {
                    CloseHandle(handle);
                }
                Err(Failure::new("EBUSY", "Terminal journal is busy."))
            }
        }
    }
}
struct Temporary<'a> {
    guard: &'a dyn Fn() -> Result<()>,
    file: File,
    attempted: bool,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if !self.attempted && (self.guard)().is_ok() {
            delete_handle(&self.file);
        }
    }
}
pub(super) fn publish(temp: &File, destination: &Path, replace: bool) -> Result<()> {
    rename_handle(temp, destination, if replace { 3 } else { 0 })
}
pub(super) fn rename_handle(temp: &File, destination: &Path, flags: u32) -> Result<()> {
    let name: Vec<u16> = destination
        .file_name()
        .ok_or_else(invalid)?
        .encode_wide()
        .collect();
    let length = size_of::<FILE_RENAME_INFO>() + name.len() * 2;
    let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
    let rename = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*rename).Anonymous.Flags = flags;
        (*rename).RootDirectory = null_mut();
        (*rename).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*rename).FileName.as_mut_ptr(), name.len());
        let mut status: IO_STATUS_BLOCK = zeroed();
        if NtSetInformationFile(
            temp.as_raw_handle(),
            &mut status,
            rename.cast(),
            length as u32,
            FileRenameInformationEx,
        ) != 0
        {
            return Err(unknown());
        }
    }
    Ok(())
}

pub(super) fn execute(
    state: &str,
    operation: &str,
    id: &str,
    nonce: &str,
    raw: Option<&str>,
) -> Result<Value> {
    execute_guarded(state, operation, id, nonce, raw, &|| Ok(()))
}
pub(super) fn execute_guarded(
    state: &str,
    operation: &str,
    id: &str,
    nonce: &str,
    raw: Option<&str>,
    guard: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    execute_impl(state, operation, id, nonce, raw, |_| {}, guard)
}
#[cfg(test)]
fn execute_with(
    state: &str,
    operation: &str,
    id: &str,
    nonce: &str,
    raw: Option<&str>,
    checkpoint: impl Fn(&str),
) -> Result<Value> {
    execute_impl(state, operation, id, nonce, raw, checkpoint, &|| Ok(()))
}
fn execute_impl(
    state: &str,
    operation: &str,
    id: &str,
    nonce: &str,
    raw: Option<&str>,
    checkpoint: impl Fn(&str),
    guard: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    guard()?;
    if !uuid(id)
        || !uuid(nonce)
        || !matches!(operation, "read" | "reserve" | "save")
        || (operation == "read") != raw.is_none()
    {
        return Err(invalid());
    }
    let next = raw.map(|r| record(r, id)).transpose()?;
    if operation == "reserve" && next.as_ref().is_none_or(|r| r.status != "starting") {
        return Err(invalid());
    }
    let (state, mut guards) = root_handles(state)?;
    ntfs(guards.last().ok_or_else(invalid)?)?;
    let private = Descriptor::private()?;
    let directory = state.join("terminal");
    let directory_security = Descriptor::private_directory()?;
    guard()?;
    if unsafe { CreateDirectoryW(wide(&directory).as_ptr(), &directory_security.attributes()) } == 0
        && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
    {
        return Err(failure());
    }
    let folder = handle(
        &directory,
        FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        None,
    )?;
    if info(&folder)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(invalid());
    }
    Descriptor::read(&folder)?.terminal_private()?;
    let _lock = Mutex::lock(&folder)?;
    guards.push(folder);
    let target = directory.join(format!("terminal-{id}.json"));
    let mut existing = match handle(
        &target,
        FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        None,
    ) {
        Ok(file) => Some(file),
        Err(e) if e.code == "ENOENT" => None,
        Err(e) => return Err(e),
    };
    let previous = if let Some(file) = existing.as_mut() {
        regular(file)?;
        Descriptor::read(file)?.terminal_private()?;
        Metadata::read(file)?;
        no_streams(&target)?;
        Some(unseal(&bytes(file)?, id)?)
    } else {
        None
    };
    if operation == "read" {
        return Ok(
            json!({"kind":if previous.is_some(){"found"}else{"missing"},"recordJson":previous}),
        );
    }
    let next = next.ok_or_else(invalid)?;
    if let Some(previous) = &previous {
        let old = record(previous, id)?;
        if !same_owner(&old, &next) {
            return Err(Failure::new(
                "ECONFLICT",
                "Existing terminal owner or inputHash differs.",
            ));
        }
        if operation == "reserve" {
            return Ok(json!({"kind":"existing","recordJson":previous}));
        }
        if rank(&next.status) < rank(&old.status)
            || (rank(&old.status) == 3 && next.status != old.status)
        {
            return Err(Failure::new(
                "ESTALE",
                "Terminal journal state would regress.",
            ));
        }
    } else if operation == "save" {
        return Err(Failure::new("ENOENT", "Terminal reservation is absent."));
    }
    if previous.is_none() {
        let mut count = 0;
        for item in std::fs::read_dir(&directory).map_err(io)? {
            item.map_err(io)?;
            count += 1;
            if count >= 2048 {
                return Err(Failure::new(
                    "ECAPACITY",
                    "Terminal journal capacity reached.",
                ));
            }
        }
    }
    let descriptor = existing.as_ref().map(Descriptor::read).transpose()?;
    let metadata = existing.as_ref().map(Metadata::read).transpose()?;
    let temp_path = directory.join(format!(".terminal-{nonce}.tmp"));
    guard()?;
    let mut temporary = Temporary {
        guard,
        file: handle(
            &temp_path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ,
            CREATE_NEW,
            Some(&private),
        )?,
        attempted: false,
    };
    private.matches(&temporary.file, false)?;
    guard()?;
    if let Some(descriptor) = &descriptor {
        descriptor.apply(&temporary.file)?;
    }
    if let Some(metadata) = &metadata {
        metadata.matches(&temporary.file)?;
    }
    let temp_security = Descriptor::read(&temporary.file)?;
    let temp_metadata = Metadata::read(&temporary.file)?;
    checkpoint("before-write");
    let encrypted = serde_json::to_vec(&json!({"format":"windows-dpapi-v1","data":encode(&dpapi(raw.ok_or_else(invalid)?.as_bytes(),true)?)?})).map_err(|_| invalid())?;
    if encrypted.len() > ENCRYPTED {
        return Err(invalid());
    }
    guard()?;
    temporary.file.write_all(&encrypted).map_err(io)?;
    temporary.file.sync_all().map_err(io)?;
    checkpoint("after-write");
    if bytes(&mut temporary.file)? != encrypted {
        return Err(invalid());
    }
    temp_security.matches(&temporary.file, true)?;
    temp_metadata.matches(&temporary.file)?;
    no_streams(&temp_path)?;
    if let Some(existing) = &mut existing {
        let mut current = handle(
            &target,
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            None,
        )?;
        let a = info(existing)?;
        let b = info(&current)?;
        if (a.dwVolumeSerialNumber, a.nFileIndexHigh, a.nFileIndexLow)
            != (b.dwVolumeSerialNumber, b.nFileIndexHigh, b.nFileIndexLow)
            || bytes(existing)? != bytes(&mut current)?
        {
            return Err(Failure::new("ECONFLICT", "Terminal record changed."));
        }
        descriptor
            .as_ref()
            .ok_or_else(invalid)?
            .matches(&current, true)?;
        metadata.as_ref().ok_or_else(invalid)?.matches(&current)?;
        no_streams(&target)?;
    }
    checkpoint("before-rename");
    guard()?;
    temporary.attempted = true;
    publish(&temporary.file, &target, previous.is_some())?;
    temporary.file.sync_all().map_err(|_| unknown())?;
    // Publication does not end handle ownership. Recheck the published object,
    // including access metadata, before issuing the single-use created receipt.
    let confirmed = (|| -> Result<()> {
        temp_security.matches(&temporary.file, true)?;
        temp_metadata.matches(&temporary.file)?;
        let mut current = handle(
            &target,
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            None,
        )?;
        let published = info(&temporary.file)?;
        let named = info(&current)?;
        if (
            published.dwVolumeSerialNumber,
            published.nFileIndexHigh,
            published.nFileIndexLow,
        ) != (
            named.dwVolumeSerialNumber,
            named.nFileIndexHigh,
            named.nFileIndexLow,
        ) || bytes(&mut current)? != encrypted
        {
            return Err(unknown());
        }
        no_streams(&target)?;
        Ok(())
    })();
    confirmed.map_err(|_| unknown())?;
    checkpoint("after-rename");
    Ok(json!({"kind":if operation == "reserve" {"created"} else {"saved"},"recordJson":raw}))
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "11111111-1111-1111-1111-111111111111";
    fn data() -> String {
        format!(
            r#"{{"requestId":"{ID}","rootId":"root","connectionId":"{}","resource":"https://fixture.test/mcp","deviceId":"{}","inputHash":"{}","status":"starting","unknown":"\ud800","nested":{{"z":1}}}}"#,
            "a".repeat(32),
            "b".repeat(32),
            "c".repeat(64)
        )
    }
    #[test]
    fn raw_unknown_json_survives_metadata_projection() {
        assert!(record(&data(), ID).is_ok());
    }
    #[test]
    fn native_reserve_roundtrip() {
        let path = std::env::temp_dir().join(format!("c2l-journal-native-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let result = execute(path.to_str().unwrap(), "reserve", ID, ID, Some(&data()));
        std::fs::remove_dir_all(&path).unwrap();
        assert!(result.is_ok(), "{result:?}");
    }
    #[test]
    fn crash_fixture() {
        let Some(point) = std::env::var_os("C2L_JOURNAL_FIXTURE_POINT") else {
            return;
        };
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let request: Value = serde_json::from_str(&input).unwrap();
        let _ = execute_with(
            request["stateDir"].as_str().unwrap(),
            request["op"].as_str().unwrap(),
            request["requestId"].as_str().unwrap(),
            request["nonce"].as_str().unwrap(),
            request["recordJson"].as_str(),
            |stage| {
                if stage == point {
                    std::process::exit(91);
                }
            },
        );
        panic!("fixture checkpoint was not reached");
    }
    #[test]
    fn process_crashes_preserve_complete_old_or_new_records() {
        use std::process::{Command, Stdio};
        for (n, stage) in [
            "before-write",
            "after-write",
            "before-rename",
            "after-rename",
        ]
        .iter()
        .enumerate()
        {
            let path =
                std::env::temp_dir().join(format!("c2l-journal-crash-{}-{n}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            let old = data();
            execute(path.to_str().unwrap(), "reserve", ID, ID, Some(&old)).unwrap();
            let next = old.replace("starting", "running");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "windows_terminal_store::tests::crash_fixture",
                    "--nocapture",
                ])
                .env("C2L_JOURNAL_FIXTURE_POINT", stage)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(serde_json::to_string(&json!({"stateDir":path,"op":"save","requestId":ID,"nonce":ID,"recordJson":next})).unwrap().as_bytes()).unwrap();
            assert_eq!(child.wait().unwrap().code(), Some(91));
            let result = execute(path.to_str().unwrap(), "read", ID, ID, None).unwrap();
            assert_eq!(
                result["recordJson"],
                if *stage == "after-rename" { next } else { old }
            );
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test]
    fn dpapi_and_strict_base64_roundtrip() {
        let input = data();
        let protected = dpapi(input.as_bytes(), true).unwrap();
        assert_eq!(
            dpapi(&decode(&encode(&protected).unwrap()).unwrap(), false).unwrap(),
            input.as_bytes()
        );
        assert!(decode("AA= ").is_err());
        assert!(decode("AAAA!").is_err());
    }
}
