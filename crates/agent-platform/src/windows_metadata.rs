//! Access-affecting SACL information is readable with READ_CONTROL. Audit-only
//! SACLs require extra privilege and are outside this preview's preservation scope.
use super::{windows::failure, windows_security::Descriptor};
use chat2local_protocol::{Failure, Result};
use std::{
    fs::File,
    mem::{size_of, zeroed},
    os::windows::io::AsRawHandle,
    ptr::null_mut,
};
use windows_sys::{
    Wdk::Storage::FileSystem::{FILE_EA_INFORMATION, FileEaInformation, NtQueryInformationFile},
    Win32::{
        Foundation::*,
        Security::{Authorization::*, *},
        System::IO::IO_STATUS_BLOCK,
    },
};

pub(super) struct Metadata(Vec<u8>);
impl Metadata {
    pub fn read(file: &File) -> Result<Self> {
        let mut ea: FILE_EA_INFORMATION = unsafe { zeroed() };
        let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
        if unsafe {
            NtQueryInformationFile(
                file.as_raw_handle(),
                &mut status,
                (&mut ea as *mut FILE_EA_INFORMATION).cast(),
                size_of::<FILE_EA_INFORMATION>() as u32,
                FileEaInformation,
            )
        } != 0
        {
            return Err(Failure::new(
                "ENOTSUP",
                "Extended metadata could not be checked.",
            ));
        }
        if ea.EaSize != 0 {
            return Err(Failure::new(
                "ENOTSUP",
                "Extended attributes are unsupported.",
            ));
        }
        let mut raw = null_mut();
        let code = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION
                    | ATTRIBUTE_SECURITY_INFORMATION
                    | SCOPE_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut raw,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(Failure::new(
                "EACL",
                "Access-affecting security metadata could not be read.",
            ));
        }
        let descriptor = Descriptor(raw);
        let mut present = 0;
        let mut acl = null_mut();
        let mut defaulted = 0;
        if unsafe {
            GetSecurityDescriptorSacl(descriptor.0, &mut present, &mut acl, &mut defaulted)
        } == 0
        {
            return Err(failure());
        }
        if present == 0 || acl.is_null() {
            return Ok(Self(Vec::new()));
        }
        for index in 0..unsafe { (*acl).AceCount } {
            let mut ace = null_mut();
            if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 {
                return Err(failure());
            }
            // Only mandatory labels may be preserved by exact comparison. Resource
            // attributes and central-access-policy ACEs are explicitly unsupported.
            if unsafe { (*ace.cast::<ACE_HEADER>()).AceType } != 17 {
                return Err(Failure::new(
                    "ENOTSUP",
                    "Complex access-affecting security is unsupported.",
                ));
            }
        }
        Ok(Self(
            unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize) }
                .to_vec(),
        ))
    }
    pub fn matches(&self, file: &File) -> Result<()> {
        if Self::read(file)?.0 != self.0 {
            return Err(Failure::new(
                "EACL",
                "Access-affecting security metadata changed.",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use windows_sys::Wdk::Storage::FileSystem::NtSetEaFile;
    #[test]
    fn real_ntfs_extended_attributes_are_refused() {
        let path = std::env::temp_dir().join(format!("c2l-ea-{}.txt", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let ea = [0u8, 0, 0, 0, 0, 3, 1, 0, b'c', b'2', b'l', 0, b'x'];
        let mut aligned = [0u32; 4];
        unsafe {
            std::ptr::copy_nonoverlapping(ea.as_ptr(), aligned.as_mut_ptr().cast(), ea.len());
        }
        let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
        let result = unsafe {
            NtSetEaFile(
                file.as_raw_handle(),
                &mut status,
                aligned.as_ptr().cast(),
                ea.len() as u32,
            )
        };
        let refused = matches!(
            Metadata::read(&file),
            Err(Failure {
                code: "ENOTSUP",
                ..
            })
        );
        drop(file);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(result, 0);
        assert!(refused);
    }
}
