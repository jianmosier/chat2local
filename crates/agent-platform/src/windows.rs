use chat2local_policy::forbidden_name;
use chat2local_protocol::{Failure, MAX_FILE_BYTES, Operation, Request, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    mem::zeroed,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf},
    ptr::null,
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*};

pub(super) fn failure() -> Failure {
    let code = match std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32 {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => "ENOENT",
        ERROR_ACCESS_DENIED => "EACCES",
        ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION => "EBUSY",
        ERROR_DIRECTORY => "ENOTDIR",
        _ => "EIO",
    };
    Failure::new(code, "Filesystem operation failed.")
}
pub(super) fn wide(path: &Path) -> Vec<u16> {
    "\\\\?\\"
        .encode_utf16()
        .chain(path.as_os_str().encode_wide())
        .chain(Some(0))
        .collect()
}
pub(super) fn info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut value = unsafe { zeroed() };
    // File owns the valid handle for the entire call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut value) } == 0 {
        return Err(failure());
    }
    Ok(value)
}
pub(super) fn open(path: &Path, directory: bool) -> Result<File> {
    let name = wide(path);
    // Never follow the last component. All preceding directories stay open without
    // write/delete sharing, so neither rename nor in-place reparse mutation can
    // change a checked directory while its descendants are being opened.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            if directory {
                FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY
            } else {
                FILE_GENERIC_READ
            },
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(failure());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(Failure::new(
            "EFILE",
            "Only regular files and directories are allowed.",
        ));
    }
    let metadata = info(&file)?;
    if metadata.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Failure::new(
            "ELINK",
            "Symbolic links and junctions are blocked.",
        ));
    }
    if (metadata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
        return Err(Failure::new("ENOTDIR", "Unexpected file type."));
    }
    Ok(file)
}

pub(super) fn root_handles(root: &str) -> Result<(PathBuf, Vec<File>)> {
    // Locally authorized drive paths only. Reject namespaces, UNC and root aliases.
    if root.contains('\0')
        || root.contains('/')
        || root.len() < 4
        || !root.as_bytes()[0].is_ascii_alphabetic()
        || &root.as_bytes()[1..3] != b":\\"
        || root.ends_with('\\')
    {
        return Err(Failure::new(
            "EPATH",
            "The authorized root changed. Select it again.",
        ));
    }
    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    for component in Path::new(root).components() {
        match component {
            Component::Prefix(_) => current.push(component.as_os_str()),
            Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
                handles.push(open(&current, true)?);
            }
            _ => return Err(Failure::new("EPATH", "Invalid authorized root.")),
        }
    }
    // Path components may normalize '.', duplicate separators or trailing spaces.
    if current.as_os_str() != Path::new(root).as_os_str() {
        return Err(Failure::new("EPATH", "Invalid authorized root."));
    }
    let mut final_name = vec![0u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            guards_last(&handles)?,
            final_name.as_mut_ptr(),
            final_name.len() as u32,
            0,
        )
    } as usize;
    if length == 0 || length >= final_name.len() {
        return Err(failure());
    }
    let canonical = String::from_utf16(&final_name[..length])
        .map_err(|_| Failure::new("EILSEQ", "Invalid root encoding."))?;
    if canonical.strip_prefix("\\\\?\\") != Some(root) {
        return Err(Failure::new(
            "EPATH",
            "The authorized root changed. Select it again.",
        ));
    }
    Ok((current, handles))
}

fn guards_last(handles: &[File]) -> Result<HANDLE> {
    handles
        .last()
        .map(|file| file.as_raw_handle() as HANDLE)
        .ok_or_else(|| Failure::new("EPATH", "Invalid authorized root."))
}

struct Search(HANDLE);
impl Drop for Search {
    fn drop(&mut self) {
        unsafe {
            FindClose(self.0);
        }
    }
}

fn list(directory: &Path) -> Result<Value> {
    let pattern = wide(&directory.join("*"));
    let mut data: WIN32_FIND_DATAW = unsafe { zeroed() };
    let handle = unsafe { FindFirstFileW(pattern.as_ptr(), &mut data) };
    if handle == INVALID_HANDLE_VALUE {
        if unsafe { GetLastError() } == ERROR_FILE_NOT_FOUND {
            return Ok(json!({"entries": [], "truncated": false}));
        }
        return Err(failure());
    }
    let _search = Search(handle);
    // Node's Windows withFileTypes readdir preserves filesystem enumeration order
    // (NTFS differs from UTF-8 and locale sorting). Filter in that same order.
    let mut entries = Vec::new();
    loop {
        let length = data
            .cFileName
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(data.cFileName.len());
        let name = String::from_utf16(&data.cFileName[..length])
            .map_err(|_| Failure::new("EILSEQ", "Invalid filename encoding."))?;
        if name != "."
            && name != ".."
            && !forbidden_name(&name)
            && data.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) == 0
        {
            entries.push(json!({"name": name, "type": if data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 { "directory" } else { "file" }}));
            if entries.len() == 501 {
                break;
            }
        }
        if unsafe { FindNextFileW(handle, &mut data) } == 0 {
            if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
                return Err(failure());
            }
            break;
        }
    }
    Ok(
        json!({"truncated": entries.len() > 500, "entries": entries.into_iter().take(500).collect::<Vec<_>>()}),
    )
}

pub fn execute(request: &Request, parts: &[&str]) -> Result<Value> {
    snapshot(request, parts, false)
}
pub(super) fn snapshot(request: &Request, parts: &[&str], may_create: bool) -> Result<Value> {
    let (mut current, mut guards) = root_handles(&request.authority.root.path)?;
    let is_directory = request.op == Operation::ListDirectory;
    for (index, part) in parts.iter().enumerate() {
        current.push(part);
        if index + 1 < parts.len() || is_directory {
            guards.push(open(&current, true)?);
        }
    }
    if is_directory {
        return list(&current);
    }
    let mut file = match open(&current, false) {
        Ok(file) => file,
        Err(error) if error.code == "ENOENT" && may_create => {
            return Ok(json!({"path":request.args.path,"content":"","sha256":null}));
        }
        Err(error) => return Err(error),
    };
    let before = info(&file)?;
    let size = ((before.nFileSizeHigh as u64) << 32) | before.nFileSizeLow as u64;
    if before.nNumberOfLinks != 1 || size > MAX_FILE_BYTES {
        return Err(Failure::new(
            "EFILE",
            "Only regular text files up to 64 KiB are supported.",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::new("EIO", "Filesystem operation failed."))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(Failure::new("EFILE", "File grew beyond the size limit."));
    }
    if info(&file)?.nNumberOfLinks != 1 {
        return Err(Failure::new(
            "EFILE",
            "Only regular, single-link files are allowed.",
        ));
    }
    if bytes.contains(&0) {
        return Err(Failure::new("EBINARY", "Binary files are not supported."));
    }
    let content = std::str::from_utf8(&bytes)
        .map_err(|_| Failure::new("ERR_ENCODING_INVALID_ENCODED_DATA", "Invalid UTF-8 text."))?;
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    Ok(
        json!({"path": request.args.path, "content": content, "sha256": hex::encode(Sha256::digest(&bytes))}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows_sys::Win32::System::{IO::DeviceIoControl, Ioctl::FSCTL_SET_REPARSE_POINT};
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "c2l-native-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn held_root_and_parent_cannot_be_replaced() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        let root = parent.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let canonical = std::fs::canonicalize(&root).unwrap();
        let root_name = canonical.to_str().unwrap().strip_prefix("\\\\?\\").unwrap();
        let (_, guards) = root_handles(root_name).unwrap();
        // Holding ancestors (including the volume) does not block sibling I/O.
        let sibling = parent.join("sibling.txt");
        std::fs::write(&sibling, "created").unwrap();
        std::fs::write(&sibling, "updated").unwrap();
        assert_eq!(std::fs::read_to_string(&sibling).unwrap(), "updated");
        assert!(std::fs::rename(&root, parent.join("moved-root")).is_err());
        assert!(std::fs::rename(&parent, fixture.0.join("moved-parent")).is_err());
        assert!(std::fs::remove_dir(&root).is_err());
        drop(guards);
        std::fs::rename(&root, parent.join("moved-root")).unwrap();
        std::fs::rename(&parent, fixture.0.join("moved-parent")).unwrap();
    }

    #[test]
    fn held_file_cannot_be_replaced_or_written() {
        let fixture = Fixture::new();
        let name = fixture.0.join("file.txt");
        std::fs::write(&name, "original").unwrap();
        let mut held = open(&name, false).unwrap();
        assert!(std::fs::rename(&name, fixture.0.join("moved.txt")).is_err());
        assert!(std::fs::write(&name, "changed").is_err());
        let mut bytes = String::new();
        held.read_to_string(&mut bytes).unwrap();
        assert_eq!(bytes, "original");
    }

    fn write_directory(path: &Path) -> std::io::Result<File> {
        let handle = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn set_junction(handle: &File, target: &Path) -> std::io::Result<()> {
        let substitute: Vec<u16> = "\\??\\"
            .encode_utf16()
            .chain(target.as_os_str().encode_wide())
            .collect();
        let print: Vec<u16> = target.as_os_str().encode_wide().collect();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&0xa0000003u32.to_le_bytes()); // Mount-point reparse tag.
        buffer.extend_from_slice(
            &((8 + (substitute.len() + print.len() + 2) * 2) as u16).to_le_bytes(),
        );
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&((substitute.len() * 2) as u16).to_le_bytes());
        buffer.extend_from_slice(&(((substitute.len() + 1) * 2) as u16).to_le_bytes());
        buffer.extend_from_slice(&((print.len() * 2) as u16).to_le_bytes());
        for unit in substitute
            .into_iter()
            .chain(Some(0))
            .chain(print)
            .chain(Some(0))
        {
            buffer.extend_from_slice(&unit.to_le_bytes());
        }
        let mut returned = 0;
        if unsafe {
            DeviceIoControl(
                handle.as_raw_handle() as HANDLE,
                FSCTL_SET_REPARSE_POINT,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[test]
    fn directory_guard_blocks_in_place_reparse_mutation() {
        let fixture = Fixture::new();
        let selected = fixture.0.join("selected");
        let outside = fixture.0.join("outside");
        std::fs::create_dir(&selected).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "outside").unwrap();
        let writer = write_directory(&selected).unwrap();
        assert_eq!(open(&selected, true).unwrap_err().code, "EBUSY");
        drop(writer);
        let held = open(&selected, true).unwrap();
        assert_eq!(
            write_directory(&selected).unwrap_err().raw_os_error(),
            Some(ERROR_SHARING_VIOLATION as i32)
        );
        assert!(set_junction(&held, &outside).is_err());
        assert_eq!(
            info(&held).unwrap().dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        assert!(!selected.join("secret.txt").exists());
        drop(held);
        // Positive control proves the same FSCTL buffer can mutate this NTFS fixture.
        let writer = write_directory(&selected).unwrap();
        set_junction(&writer, &outside).unwrap();
        drop(writer);
        assert_eq!(
            std::fs::read_to_string(selected.join("secret.txt")).unwrap(),
            "outside"
        );
        assert_eq!(open(&selected, true).unwrap_err().code, "ELINK");
        std::fs::remove_dir(&selected).unwrap();
    }
}
