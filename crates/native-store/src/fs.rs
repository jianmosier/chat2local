use crate::{Error, Result};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};
pub(crate) fn rename(
    source: &Path,
    destination: &Path,
    guard: &dyn Fn() -> Result<()>,
) -> Result<()> {
    guard()?;
    #[cfg(windows)]
    {
        chat2local_agent_platform::rename_private(source, destination, &|| guard().is_ok())
            .map_err(|e| Error::new(e.code, e.message))
    }
    #[cfg(not(windows))]
    {
        guard()?;
        Ok(std::fs::rename(source, destination)?)
    }
}

pub(crate) fn mkdir(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    Ok(builder.create(path)?)
}
pub(crate) fn create(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        options
            .access_mode(FILE_GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
pub(crate) fn publish_scoped(
    file: &File,
    source: &Path,
    destination: &Path,
    guard: &dyn Fn() -> Result<()>,
    admission: &crate::PublicationScope<'_>,
) -> Result<()> {
    #[cfg(windows)]
    {
        chat2local_agent_platform::publish_private_scoped(
            file,
            source,
            destination,
            &|| guard().is_ok(),
            &|work| {
                admission(&mut || work().map_err(|e| Error::new(e.code, e.message))).map_err(|e| {
                    chat2local_protocol::Failure::new(
                        e.code,
                        "Scoped Store publication was refused.",
                    )
                })
            },
        )
        .map_err(|e| Error::new(e.code, e.message))
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        admission(&mut || rename(source, destination, guard))
    }
}
pub(crate) fn parent_safe(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::invalid("Private storage cannot be a link."));
        }
    }
    if meta.file_type().is_symlink() {
        return Err(Error::invalid("Private storage cannot be a link."));
    }
    Ok(())
}
#[cfg(windows)]
fn info(
    file: &File,
) -> Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;
    let mut info = unsafe { std::mem::zeroed() };
    if unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
            file.as_raw_handle(),
            &mut info,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(info)
}
pub(crate) fn open_private(path: &Path, limit: u64) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        let identity = info(&file)?;
        if identity.nNumberOfLinks != 1
            || identity.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(Error::invalid("Unsafe private record."));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err(Error::invalid("Unsafe private record."));
        }
    }
    if !meta.is_file() || meta.len() > limit {
        return Err(Error::invalid("Unsafe private record."));
    }
    Ok(file)
}
pub(crate) fn single_link(path: &Path) -> Result<bool> {
    #[cfg(windows)]
    {
        let mut options = OpenOptions::new();
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        };
        options
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        Ok(info(&options.open(path)?)?.nNumberOfLinks == 1)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(std::fs::symlink_metadata(path)?.nlink() == 1)
    }
}
pub(crate) fn append_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    #[cfg(windows)]
    {
        let i = info(&file)?;
        if i.nNumberOfLinks != 1
            || i.dwFileAttributes
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
        {
            return Err(Error::invalid("Unsafe audit record."));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file.metadata()?.nlink() != 1 {
            return Err(Error::invalid("Unsafe audit record."));
        }
    }
    if !file.metadata()?.is_file() {
        return Err(Error::invalid("Unsafe audit record."));
    }
    Ok(file)
}
pub fn same_directory(first: &Path, second: &Path) -> Result<bool> {
    let a = std::fs::canonicalize(first)?;
    let b = std::fs::canonicalize(second)?;
    if a == b {
        return Ok(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
        };
        let open = |path: &Path| {
            let mut options = OpenOptions::new();
            options
                .access_mode(FILE_READ_ATTRIBUTES)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
            options.open(path)
        };
        let a = info(&open(&a)?)?;
        let b = info(&open(&b)?)?;
        Ok(a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && b.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && (a.nFileIndexHigh != 0 || a.nFileIndexLow != 0)
            && a.dwVolumeSerialNumber == b.dwVolumeSerialNumber
            && a.nFileIndexHigh == b.nFileIndexHigh
            && a.nFileIndexLow == b.nFileIndexLow)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = std::fs::metadata(a)?;
        let b = std::fs::metadata(b)?;
        Ok(a.is_dir() && b.is_dir() && a.ino() != 0 && a.dev() == b.dev() && a.ino() == b.ino())
    }
}
