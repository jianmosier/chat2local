//! Nonbuffered control submission: WriteFile itself is the RUN linearization point.
use super::{
    windows::{failure, open, root_handles},
    windows_security::Descriptor,
};
use chat2local_protocol::{Failure, Result};
use std::{
    fs::File,
    io::Read,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr::{null, null_mut},
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{IO::*, Pipes::*, Threading::*},
};
pub struct TrustedExecutable {
    pub path: std::path::PathBuf,
    _handles: Vec<File>,
}
pub struct SystemExecutable {
    pub path: std::path::PathBuf,
    _handles: Vec<File>,
}
pub fn system_powershell() -> Result<SystemExecutable> {
    let mut directory = vec![0u16; 32768];
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            directory.as_mut_ptr(),
            directory.len() as u32,
        )
    } as usize;
    if length == 0 || length >= directory.len() {
        return Err(failure());
    }
    let directory = String::from_utf16(&directory[..length]).map_err(|_| failure())?;
    let path = Path::new(&directory)
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    // System APIs and the on-disk name may use different casing. Walk and hold
    // the API-provided path without following reparses, then obtain its exact
    // spelling from that handle; do not relax user-authorized root validation.
    let mut checked = std::path::PathBuf::new();
    let mut handles = Vec::new();
    for component in path.parent().ok_or_else(failure)?.components() {
        use std::path::Component;
        match component {
            Component::Prefix(_) => checked.push(component.as_os_str()),
            Component::RootDir | Component::Normal(_) => {
                checked.push(component.as_os_str());
                handles.push(open(&checked, true)?);
            }
            _ => return Err(failure()),
        }
    }
    let mut exact = vec![0u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            handles.last().ok_or_else(failure)?.as_raw_handle(),
            exact.as_mut_ptr(),
            exact.len() as u32,
            0,
        )
    } as usize;
    if length == 0 || length >= exact.len() {
        return Err(failure());
    }
    let exact = String::from_utf16(&exact[..length]).map_err(|_| failure())?;
    let path = Path::new(exact.strip_prefix("\\\\?\\").ok_or_else(failure)?).join("powershell.exe");
    handles.push(open(&path, false)?);
    Ok(SystemExecutable {
        path,
        _handles: handles,
    })
}
#[test]
fn system_powershell_uses_checked_native_system_directory() {
    let executable = system_powershell().unwrap();
    assert!(executable.path.is_absolute());
    assert_eq!(executable.path.file_name().unwrap(), "powershell.exe");
}
impl TrustedExecutable {
    pub fn open(path: &Path, hash: &str) -> Result<Self> {
        use sha2::{Digest, Sha256};
        let parent = path.parent().and_then(Path::to_str).ok_or_else(failure)?;
        let (_, mut handles) = root_handles(parent)?;
        let mut file = open(path, false)?;
        let metadata = file.metadata().map_err(|_| failure())?;
        if metadata.len() > 128 * 1024 * 1024 {
            return Err(failure());
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| failure())?;
        if hex::encode(Sha256::digest(&bytes)) != hash {
            return Err(Failure::new(
                "EPROVENANCE",
                "Native helper provenance mismatch.",
            ));
        }
        handles.push(file);
        Ok(Self {
            path: path.to_owned(),
            _handles: handles,
        })
    }
}
pub struct ControlPipe {
    file: Arc<File>,
}
pub struct Submission {
    file: Arc<File>,
    bytes: Box<[u8]>,
    overlapped: Box<OVERLAPPED>,
    _event: OwnedHandle,
    complete: bool,
    pending: bool,
}
// OVERLAPPED and its buffer have stable heap addresses, exclusively owned until completion.
unsafe impl Send for Submission {}
impl ControlPipe {
    pub fn pair(nonce: &str) -> Result<(Self, File)> {
        Self::with_capacity(nonce, 65536)
    }
    pub fn with_capacity(nonce: &str, capacity: u32) -> Result<(Self, File)> {
        if !(256..=65536).contains(&capacity) {
            return Err(failure());
        }
        if nonce.len() != 64 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(failure());
        }
        let path = std::path::PathBuf::from(format!(
            "\\\\.\\pipe\\chat2local-control-{}-{nonce}",
            std::process::id()
        ));
        let name = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let descriptor = Descriptor::private()?;
        let attributes = descriptor.attributes();
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                capacity,
                capacity,
                0,
                &attributes,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(failure());
        }
        let parent = unsafe { File::from_raw_handle(raw) };
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(failure());
        }
        let child = unsafe { File::from_raw_handle(raw) };
        // Opening the only client before ConnectNamedPipe is the documented connected case.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(failure());
        }
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut connection: OVERLAPPED = unsafe { std::mem::zeroed() };
        connection.hEvent = event.as_raw_handle();
        if unsafe { ConnectNamedPipe(parent.as_raw_handle(), &mut connection) } == 0 {
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => {}
                ERROR_IO_PENDING => {
                    unsafe {
                        CancelIoEx(parent.as_raw_handle(), &connection);
                        let mut completed = 0;
                        GetOverlappedResult(parent.as_raw_handle(), &connection, &mut completed, 1);
                    }
                    return Err(failure());
                }
                _ => return Err(failure()),
            }
        }

        Ok((
            Self {
                file: Arc::new(parent),
            },
            child,
        ))
    }
    pub fn cancel_pending(&self) {
        unsafe {
            CancelIoEx(self.file.as_raw_handle(), null());
        }
    }
    pub fn submit(&self, bytes: Vec<u8>) -> Result<Submission> {
        if bytes.is_empty() || bytes.len() > 256 * 1024 {
            return Err(failure());
        }
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(failure());
        }
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
        overlapped.hEvent = event.as_raw_handle();
        let bytes = bytes.into_boxed_slice();
        let ok = unsafe {
            WriteFile(
                self.file.as_raw_handle(),
                bytes.as_ptr(),
                bytes.len() as u32,
                null_mut(),
                &mut *overlapped,
            )
        };
        if ok == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(failure());
        }
        Ok(Submission {
            file: self.file.clone(),
            bytes,
            overlapped,
            _event: event,
            complete: false,
            pending: ok == 0,
        })
    }
}
impl Submission {
    pub fn pending(&self) -> bool {
        self.pending
    }
    pub fn complete(mut self) -> Result<()> {
        let mut sent = 0;
        let ok = unsafe {
            GetOverlappedResult(self.file.as_raw_handle(), &*self.overlapped, &mut sent, 1)
        };
        self.complete = true;
        if ok == 0 || sent as usize != self.bytes.len() {
            Err(failure())
        } else {
            Ok(())
        }
    }
}
impl Drop for Submission {
    fn drop(&mut self) {
        if !self.complete {
            unsafe {
                CancelIoEx(self.file.as_raw_handle(), &*self.overlapped);
                let mut sent = 0;
                GetOverlappedResult(self.file.as_raw_handle(), &*self.overlapped, &mut sent, 1);
            }
        }
    }
}
