//! Read-only process identity. A held handle prevents PID reuse during inspection.
use std::io;
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, WAIT_OBJECT_0},
    System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        QueryFullProcessImageNameW, WaitForSingleObject,
    },
};

pub struct ProcessOwner {
    handle: HANDLE,
}
/// Keep creation identity even when Windows cannot resolve an exited image.
pub struct ProcessProbe {
    pub exited: bool,
    pub created: String,
    pub image: Result<String, i32>,
}
// The handle is owned and only queried; no process mutation is exposed.
unsafe impl Send for ProcessOwner {}
unsafe impl Sync for ProcessOwner {}
impl Drop for ProcessOwner {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
impl ProcessOwner {
    pub fn open(pid: u32) -> io::Result<Option<Self>> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        Ok(Some(Self { handle }))
    }
    pub fn exited(&self) -> io::Result<bool> {
        match unsafe { WaitForSingleObject(self.handle, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            258 => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }
    fn created(&self) -> io::Result<String> {
        let mut created = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe { GetProcessTimes(self.handle, &mut created, &mut exit, &mut kernel, &mut user) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(((created.dwHighDateTime as u64) << 32 | created.dwLowDateTime as u64).to_string())
    }
    fn image(&self) -> io::Result<String> {
        let mut image = vec![0u16; 32768];
        let mut length = image.len() as u32;
        if unsafe { QueryFullProcessImageNameW(self.handle, 0, image.as_mut_ptr(), &mut length) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        String::from_utf16(&image[..length as usize])
            .map_err(|_| io::Error::other("Invalid process image"))
    }
    pub fn identity(&self) -> io::Result<(String, String)> {
        Ok((self.created()?, self.image()?))
    }
    pub fn probe(&self) -> io::Result<ProcessProbe> {
        Ok(ProcessProbe {
            exited: self.exited()?,
            created: self.created()?,
            image: self
                .image()
                .map_err(|error| error.raw_os_error().unwrap_or(-1)),
        })
    }
}

/// Require exclusive ownership before binding a Windows socket.
pub fn exclusive_socket(socket: std::os::windows::io::RawSocket) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{
        SO_EXCLUSIVEADDRUSE, SOL_SOCKET, WSAGetLastError, setsockopt,
    };
    let enabled = 1i32;
    if unsafe {
        setsockopt(
            socket as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            std::mem::size_of_val(&enabled) as i32,
        )
    } != 0
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn held_current_process_reports_stable_creation_and_image() {
        let owner = ProcessOwner::open(std::process::id()).unwrap().unwrap();
        let first = owner.identity().unwrap();
        assert!(!owner.exited().unwrap());
        assert_eq!(owner.identity().unwrap(), first);
        assert!(first.0.parse::<u64>().unwrap() > 0);
        assert!(!first.1.is_empty());
    }
}
