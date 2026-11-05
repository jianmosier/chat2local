//! Held, non-reparse directory adapters shared by native command orchestration.
use super::{
    windows::{failure, info, open, root_handles, wide},
    windows_write::handle,
};
use chat2local_protocol::{Failure, Result};
use std::{
    fs::File,
    path::{Path, PathBuf},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::TOKEN_QUERY,
    Storage::FileSystem::*,
    System::{
        SystemInformation::GetSystemWindowsDirectoryW,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
    UI::Shell::GetUserProfileDirectoryW,
};
fn denied() -> Failure {
    Failure::new("EACCESS", "Protected or unsafe command directory.")
}
/// Same-directory Store publication while command directory guards are held.
/// Uses the existing normal-access-checking NT rename, never bypass class 66.
pub fn rename_private(source: &Path, destination: &Path, guard: &dyn Fn() -> bool) -> Result<()> {
    let file = handle(
        source,
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        None,
    )?;
    publish_private(&file, source, destination, guard)
}
pub fn publish_private(
    file: &File,
    source: &Path,
    destination: &Path,
    guard: &dyn Fn() -> bool,
) -> Result<()> {
    publish_private_scoped(file, source, destination, guard, &|work| work())
}
pub fn publish_private_scoped(
    file: &File,
    source: &Path,
    destination: &Path,
    guard: &dyn Fn() -> bool,
    admission: &crate::PublicationScope<'_>,
) -> Result<()> {
    let source = std::path::absolute(source).map_err(|_| denied())?;
    let destination = std::path::absolute(destination).map_err(|_| denied())?;
    let parent = source.parent().ok_or_else(denied)?;
    if destination.parent() != Some(parent) {
        return Err(denied());
    }
    let (_path, _parents) = root_handles(parent.to_str().ok_or_else(denied)?)?;
    let metadata = info(file)?;
    if metadata.nNumberOfLinks != 1 || metadata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(denied());
    }
    let named = handle(
        &source,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        None,
    )?;
    let identity = |file: &File| {
        info(file).map(|i| (i.dwVolumeSerialNumber, i.nFileIndexHigh, i.nFileIndexLow))
    };
    if identity(file)? != identity(&named)? {
        return Err(denied());
    }
    let target = match handle(
        &destination,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        None,
    ) {
        Ok(f) => {
            let i = info(&f)?;
            if i.nNumberOfLinks != 1 || i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                return Err(denied());
            }
            Some(f)
        }
        Err(e) if e.code == "ENOENT" => None,
        Err(e) => return Err(e),
    };
    // Keep the source and parent chain bound. Normal replacement refuses a
    // destination with an open handle, even our metadata-only handle. Close
    // that snapshot before submission, retaining the legacy optimistic
    // replacement contract rather than adding POSIX/ignore-sharing semantics.
    let replace = target.is_some();
    drop(target);
    if !guard() {
        return Err(Failure::new(
            "EOWNER",
            "Store publication ownership changed.",
        ));
    }
    // Replace only. In particular, do not request POSIX/ignore-sharing behavior.
    admission(&mut || {
        if !guard() {
            return Err(Failure::new(
                "EOWNER",
                "Store publication ownership changed.",
            ));
        }
        super::windows_terminal_store::rename_handle(file, &destination, u32::from(replace))
    })
}
fn within(a: &str, b: &str) -> bool {
    let a = a.trim_end_matches('\\').to_lowercase();
    let b = b.trim_end_matches('\\').to_lowercase();
    a == b || b.starts_with(&(a + "\\"))
}
fn private_root(root: &str, state: &str) -> Result<()> {
    if within(root, state) || within(state, root) {
        return Err(denied());
    }
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(failure());
    }
    let mut home = vec![0u16; 32768];
    let mut size = home.len() as u32;
    let ok = unsafe { GetUserProfileDirectoryW(token, home.as_mut_ptr(), &mut size) };
    unsafe {
        CloseHandle(token);
    }
    if ok == 0 {
        return Err(failure());
    }
    let home =
        String::from_utf16(&home[..size.saturating_sub(1) as usize]).map_err(|_| denied())?;
    if root.eq_ignore_ascii_case(&home) {
        return Err(denied());
    }
    let mut system = vec![0u16; 32768];
    let size =
        unsafe { GetSystemWindowsDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    if size == 0 || size >= system.len() {
        return Err(failure());
    }
    let system = String::from_utf16(&system[..size]).map_err(|_| denied())?;
    let mut protected = vec![system];
    for key in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Ok(path) = std::env::var(key) {
            protected.push(path);
        }
    }
    if protected.iter().any(|p| within(p, root) || within(root, p)) {
        return Err(denied());
    }
    Ok(())
}
pub struct GuardedDirectory {
    pub path: PathBuf,
    _handles: Vec<File>,
}
impl GuardedDirectory {
    pub fn open(root: &str, relative: &str, state: &str) -> Result<Self> {
        private_root(root, state)?;
        if relative.encode_utf16().count() > 2048
            || relative.starts_with(['/', '\\'])
            || relative.chars().any(|c| c <= '\u{1f}' || c == ':')
            || relative.split(['/', '\\']).any(|p| p == "..")
        {
            return Err(denied());
        }
        let (mut path, mut handles) = root_handles(root)?;
        for part in relative
            .split(['/', '\\'])
            .filter(|p| !p.is_empty() && *p != ".")
        {
            path.push(part);
            handles.push(open(&path, true)?);
        }
        Ok(Self {
            path,
            _handles: handles,
        })
    }
    pub fn root(root: &str, state: &str) -> Result<Self> {
        Self::open(root, ".", state)
    }
}
pub struct WriteGate {
    file: File,
    _parents: Vec<File>,
    guard: crate::PublicationGuard,
}
impl WriteGate {
    pub fn acquire(state: &str, guard: crate::PublicationGuard) -> Result<Self> {
        guard()?;
        let (path, parents) = root_handles(state)?;
        let gate = path.join("write-gate");
        guard()?;
        if unsafe { CreateDirectoryW(wide(&gate).as_ptr(), std::ptr::null()) } == 0 {
            return Err(Failure::new("EFENCE", "Write storage is fenced."));
        }
        let file = handle(
            &gate,
            FILE_READ_ATTRIBUTES | DELETE,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            None,
        )?;
        if info(&file)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(denied());
        }
        Ok(Self {
            file,
            _parents: parents,
            guard,
        })
    }
    pub fn release(self) -> Result<()> {
        (self.guard)()?;
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        use std::os::windows::io::AsRawHandle;
        if unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle(),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(failure());
        }
        Ok(())
    }
}
