//! Local shell primitives. Paths are held without following reparses.
use super::windows::{failure, info, open};
use chat2local_protocol::{Failure, Result};
use std::{
    fs::File,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::{Component, Path, PathBuf},
};
use windows_sys::Win32::{Storage::FileSystem::*, UI::Shell::SHGetFolderPathW};
fn denied() -> Failure {
    Failure::new("EPATH", "系统目录和 Chat2Local 凭据目录不可浏览或授权。")
}
pub fn shell_folder(id: i32) -> Result<PathBuf> {
    let mut out = [0u16; 260];
    if unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            id,
            std::ptr::null_mut(),
            0,
            out.as_mut_ptr(),
        )
    } < 0
    {
        return Err(failure());
    }
    use std::os::windows::ffi::OsStringExt;
    Ok(
        std::ffi::OsString::from_wide(&out[..out.iter().position(|v| *v == 0).ok_or_else(denied)?])
            .into(),
    )
}
pub fn within(base: &Path, target: &Path) -> bool {
    let a = base
        .as_os_str()
        .encode_wide()
        .map(|u| if (65..=90).contains(&u) { u + 32 } else { u })
        .collect::<Vec<_>>();
    let b = target
        .as_os_str()
        .encode_wide()
        .map(|u| if (65..=90).contains(&u) { u + 32 } else { u })
        .collect::<Vec<_>>();
    let a = a.strip_suffix(&[92]).unwrap_or(&a);
    b == a || b.starts_with(a) && b.get(a.len()) == Some(&92)
}
pub struct ShellDirectory {
    pub path: PathBuf,
    handles: Vec<File>,
}
impl ShellDirectory {
    pub fn open(path: &Path) -> Result<Self> {
        let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if units.len() > 2048
            || units.len() < 3
            || !((units[0] as u8).is_ascii_alphabetic())
            || units[1] != 58
            || units[2] != 92
            || units.iter().any(|u| *u < 32 || *u == 127 || *u == 47)
        {
            return Err(denied());
        }
        let mut checked = PathBuf::new();
        let mut handles = Vec::new();
        for c in path.components() {
            match c {
                Component::Prefix(_) => checked.push(c.as_os_str()),
                Component::RootDir | Component::Normal(_) => {
                    checked.push(c.as_os_str());
                    handles.push(open(&checked, true)?);
                }
                _ => return Err(denied()),
            }
        }
        let mut final_path = vec![0u16; 32768];
        let n = unsafe {
            GetFinalPathNameByHandleW(
                handles.last().ok_or_else(denied)?.as_raw_handle(),
                final_path.as_mut_ptr(),
                final_path.len() as u32,
                0,
            )
        } as usize;
        if n == 0 || n >= final_path.len() || !final_path[..n].starts_with(&[92, 92, 63, 92]) {
            return Err(denied());
        }
        use std::os::windows::ffi::OsStringExt;
        Ok(Self {
            path: std::ffi::OsString::from_wide(&final_path[4..n]).into(),
            handles,
        })
    }
    pub fn same(&self, path: &Path) -> bool {
        self.same_checked(path).unwrap_or(false)
    }
    /// The Windows volume serial and 64-bit file index used by libuv stat.
    /// Decimal strings keep the full integer range of Node's bigint stat API.
    pub fn node_identity(&self) -> Result<(String, String)> {
        let i = info(self.handles.last().ok_or_else(denied)?)?;
        Ok((
            i.dwVolumeSerialNumber.to_string(),
            (((i.nFileIndexHigh as u64) << 32) | i.nFileIndexLow as u64).to_string(),
        ))
    }
    pub fn same_checked(&self, path: &Path) -> Result<bool> {
        let other = Self::open(path)?;
        let identity =
            |f: &File| info(f).map(|i| (i.dwVolumeSerialNumber, i.nFileIndexHigh, i.nFileIndexLow));
        Ok(identity(self.handles.last().unwrap())? == identity(other.handles.last().unwrap())?)
    }
}
pub struct FolderBrowse {
    pub directory: ShellDirectory,
    pub home: PathBuf,
    protected: Vec<PathBuf>,
    state: PathBuf,
}
pub struct BrowseEntry {
    pub name: Vec<u16>,
    pub path: Vec<u16>,
}
impl FolderBrowse {
    pub fn open(input: Option<&str>, state: &Path) -> Result<Self> {
        let home = ShellDirectory::open(&shell_folder(0x28)?)?.path;
        let directory = ShellDirectory::open(input.map(Path::new).unwrap_or(&home))?;
        let mut windows = [0u16; 32768];
        let n = unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(
                windows.as_mut_ptr(),
                windows.len() as u32,
            )
        } as usize;
        if n == 0 || n >= windows.len() {
            return Err(failure());
        }
        use std::os::windows::ffi::OsStringExt;
        let state = ShellDirectory::open(state)?.path;
        let mut protected = vec![
            state.clone(),
            state
                .parent()
                .ok_or_else(denied)?
                .join("Chat2LocalOperator"),
            std::ffi::OsString::from_wide(&windows[..n]).into(),
            shell_folder(0x26)?,
        ];
        if let Ok(x86) = shell_folder(0x2a) {
            protected.push(x86);
        }
        if protected.iter().any(|p| within(p, &directory.path)) {
            return Err(denied());
        }
        Ok(Self {
            directory,
            home,
            protected,
            state,
        })
    }
    pub fn selectable(&self) -> bool {
        self.selectable_checked().unwrap_or(false)
    }
    pub fn selectable_checked(&self) -> Result<bool> {
        Ok(self.directory.path.parent().is_some()
            && !self.directory.same_checked(&self.home)?
            && !within(&self.directory.path, &self.state)
            && !self
                .protected
                .iter()
                .any(|p| within(&self.directory.path, p)))
    }
    pub fn entries(&self) -> Result<(Vec<BrowseEntry>, bool)> {
        let mut entries = Vec::new();
        let mut truncated = false;
        for entry in std::fs::read_dir(&self.directory.path).map_err(|_| failure())? {
            let entry = entry.map_err(|_| failure())?;
            let name = entry.file_name();
            let units = name.encode_wide().collect::<Vec<_>>();
            let lower = name.to_string_lossy().to_ascii_lowercase();
            if units.first() == Some(&46)
                || [
                    "node_modules",
                    "chat2localoperator",
                    "system volume information",
                    "$recycle.bin",
                ]
                .contains(&lower.as_str())
            {
                continue;
            }
            let meta = std::fs::symlink_metadata(entry.path()).map_err(|_| failure())?;
            use std::os::windows::fs::MetadataExt;
            if !meta.is_dir()
                || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || self.protected.iter().any(|p| within(p, &entry.path()))
            {
                continue;
            }
            if entries.len() == 300 {
                truncated = true;
                break;
            }
            entries.push(BrowseEntry {
                name: units,
                path: entry.path().as_os_str().encode_wide().collect(),
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok((entries, truncated))
    }
}
/// A checked existing entry is kept immutable until its own handle is deleted.
pub struct ShellFile {
    file: File,
}
impl ShellFile {
    pub fn open(path: &Path) -> Result<Option<Self>> {
        let file = match super::windows_write::handle(
            path,
            DELETE | FILE_READ_ATTRIBUTES | windows_sys::Win32::Foundation::GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            None,
        ) {
            Ok(file) => file,
            Err(e) if e.code == "ENOENT" => return Ok(None),
            Err(e) => return Err(e),
        };
        let i = info(&file)?;
        if i.nNumberOfLinks != 1
            || i.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        {
            return Err(denied());
        }
        Ok(Some(Self { file }))
    }
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        use std::io::Read;
        let mut bytes = Vec::new();
        (&self.file)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure())?;
        if bytes.len() > 1024 * 1024 {
            return Err(denied());
        }
        Ok(bytes)
    }
    pub fn delete(self) -> Result<()> {
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
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
    pub fn identity(&self) -> Result<(u32, u32, u32)> {
        shell_file_identity(&self.file)
    }
    pub fn publish(&self, destination: &Path) -> Result<()> {
        super::windows_terminal_store::rename_handle(&self.file, destination, 0)
    }
    /// Replace the checked immutable entry at the same optimistic commit boundary
    /// used by Store publication. Callers retain verified previous bytes first.
    pub fn replace_checked(&self, destination: &Path, previous: Self) -> Result<()> {
        let named = super::windows_write::handle(
            destination,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            None,
        )?;
        if shell_file_identity(&named)? != previous.identity()? {
            return Err(denied());
        }
        // Normal Windows replacement rejects an open destination, including a
        // metadata-only handle. Close only these snapshots at commit, keeping
        // the prepared file and caller's directory/session guards held.
        drop(named);
        drop(previous);
        super::windows_terminal_store::rename_handle(&self.file, destination, 3)
    }
}
pub fn hold_shell_read(path: &Path) -> Result<File> {
    open(path, false)
}
pub fn shell_file_identity(file: &File) -> Result<(u32, u32, u32)> {
    let i = info(file)?;
    Ok((i.dwVolumeSerialNumber, i.nFileIndexHigh, i.nFileIndexLow))
}
#[test]
fn shell_publication_never_replaces_an_unchecked_arrival() {
    let directory = std::env::temp_dir().join(format!("c2l-shell-publish-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let source = directory.join("source.lnk");
    let target = directory.join("target.lnk");
    std::fs::write(&source, b"prepared").unwrap();
    std::fs::write(&target, b"foreign").unwrap();
    let held = ShellFile::open(&source).unwrap().unwrap();
    assert!(held.publish(&target).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"foreign");
    drop(held);
    std::fs::remove_dir_all(directory).unwrap();
}
#[test]
fn shell_checked_replacement_holds_the_old_entry_and_its_directory() {
    let directory = std::env::temp_dir().join(format!("c2l-shell-replace-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let held_directory = ShellDirectory::open(&directory).unwrap();
    let source = held_directory.path.join("prepared.tmp");
    let target = held_directory.path.join("Chat2Local.cmd");
    std::fs::write(&source, b"prepared").unwrap();
    std::fs::write(&target, b"previous").unwrap();
    let prepared = ShellFile::open(&source).unwrap().unwrap();
    let previous = ShellFile::open(&target).unwrap().unwrap();
    assert_eq!(previous.snapshot().unwrap(), b"previous");
    prepared.replace_checked(&target, previous).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"prepared");
    drop((prepared, held_directory));
    std::fs::remove_dir_all(directory).unwrap();
}
