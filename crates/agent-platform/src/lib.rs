use chat2local_protocol::{Request, Result};
use serde_json::Value;

/// Matches the operating-system DNS hostname used by libuv on Windows.
pub fn computer_name() -> Result<String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::{
            ComputerNameDnsHostname, GetComputerNameExW,
        };
        let mut buffer = [0u16; 256];
        let mut size = buffer.len() as u32;
        if unsafe { GetComputerNameExW(ComputerNameDnsHostname, buffer.as_mut_ptr(), &mut size) }
            == 0
        {
            return Err(chat2local_protocol::Failure::new(
                "EIO",
                "Computer name unavailable.",
            ));
        }
        String::from_utf16(&buffer[..size as usize])
            .map_err(|_| chat2local_protocol::Failure::new("EIO", "Invalid computer name."))
    }
    #[cfg(not(windows))]
    {
        Err(chat2local_protocol::Failure::new(
            "ENOTSUP",
            "Native computer metadata requires Windows.",
        ))
    }
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_dpapi;
#[cfg(windows)]
pub use windows_dpapi::current_user_data;
#[cfg(windows)]
mod windows_metadata;
#[cfg(windows)]
mod windows_security;
#[cfg(windows)]
mod windows_terminal_store;
#[cfg(windows)]
mod windows_write;
pub fn terminal_record(
    state: &str,
    operation: &str,
    id: &str,
    nonce: &str,
    record: Option<&str>,
) -> Result<Value> {
    #[cfg(windows)]
    {
        windows_terminal_store::execute(state, operation, id, nonce, record)
    }
    #[cfg(not(windows))]
    {
        let _ = (state, operation, id, nonce, record);
        Err(chat2local_protocol::Failure::new(
            "ENOTSUP",
            "Native terminal storage requires Windows NTFS.",
        ))
    }
}
#[cfg(windows)]
pub use windows_write::PreparedWrite;

#[cfg(not(windows))]
pub struct PreparedWrite;
#[cfg(not(windows))]
impl PreparedWrite {
    pub fn prepare(_: &chat2local_protocol::WriteRequest, _: &str) -> Result<Self> {
        Err(chat2local_protocol::Failure::new(
            "ENOTSUP",
            "Rust writing requires Windows NTFS.",
        ))
    }
    pub fn commit(&mut self) -> Result<Value> {
        unreachable!()
    }
}

pub fn execute(request: &Request) -> Result<Value> {
    let parts = chat2local_policy::authorize(request)?;
    #[cfg(windows)]
    {
        windows::execute(request, &parts)
    }
    #[cfg(not(windows))]
    {
        let _ = parts;
        Err(chat2local_protocol::Failure::new(
            "ENOTSUP",
            "Rust readonly backend currently requires Windows.",
        ))
    }
}

#[cfg(windows)]
mod windows_owner;
#[cfg(windows)]
pub use windows_owner::{ProcessOwner, ProcessProbe, exclusive_socket};

pub type PublicationGuard = std::sync::Arc<dyn Fn() -> Result<()> + Send + Sync>;
/// Caller retains its authority guards while invoking the actual publication once.
pub type PublicationScope<'a> = dyn Fn(&mut dyn FnMut() -> Result<()>) -> Result<()> + 'a;
#[cfg(windows)]
mod windows_adapters;
#[cfg(windows)]
pub use windows_adapters::{
    GuardedDirectory, WriteGate, publish_private, publish_private_scoped, rename_private,
};
pub fn snapshot(request: &Request, may_create: bool) -> Result<Value> {
    let parts = chat2local_policy::authorize(request)?;
    #[cfg(windows)]
    {
        windows::snapshot(request, &parts, may_create)
    }
    #[cfg(not(windows))]
    {
        let _ = (parts, may_create);
        Err(chat2local_protocol::Failure::new(
            "ENOTSUP",
            "Native snapshots require Windows.",
        ))
    }
}
pub fn terminal_record_guarded(
    state: &str,
    operation: &str,
    id: &str,
    nonce: &str,
    raw: Option<&str>,
    guard: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    #[cfg(windows)]
    {
        windows_terminal_store::execute_guarded(state, operation, id, nonce, raw, guard)
    }
    #[cfg(not(windows))]
    {
        let _ = (state, operation, id, nonce, raw, guard);
        Err(chat2local_protocol::Failure::new(
            "ENOTSUP",
            "Native journal requires Windows.",
        ))
    }
}

#[cfg(windows)]
mod windows_control_pipe;
#[cfg(windows)]
pub use windows_control_pipe::{
    ControlPipe, Submission, SystemExecutable, TrustedExecutable, system_powershell,
};
#[cfg(windows)]
mod windows_shell;
#[cfg(windows)]
pub use windows_shell::{
    FolderBrowse, ShellDirectory, ShellFile, hold_shell_read, shell_file_identity, shell_folder,
    within,
};
