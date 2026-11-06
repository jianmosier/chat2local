//! Handle-based Windows security. Never substitute Unix mode bits for a DACL.
use super::windows::failure;
use chat2local_protocol::{Failure, Result};
use std::{fs::File, mem::size_of, os::windows::io::AsRawHandle, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::Threading::*,
};

pub(super) struct Descriptor(pub PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

impl Descriptor {
    pub fn matches_mutex(&self, handle: HANDLE) -> Result<()> {
        let mut raw = null_mut();
        if unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut raw,
            )
        } != ERROR_SUCCESS
        {
            return Err(Failure::new("EACL", "Mutex security could not be read."));
        }
        let other = Self(raw);
        let a = self.dacl()?;
        let b = other.dacl()?;
        if unsafe { EqualSid(self.owner()?, other.owner()?) } == 0
            || unsafe {
                std::slice::from_raw_parts(a.cast::<u8>(), (*a).AclSize as usize)
                    != std::slice::from_raw_parts(b.cast::<u8>(), (*b).AclSize as usize)
            }
        {
            return Err(Failure::new(
                "EACL",
                "Mutex security differs from its private descriptor.",
            ));
        }
        Ok(())
    }
    /// Legacy private directories may inherit Administrator/System ACEs. Never
    /// broaden them; reject grants to other principals rather than repair ACLs.
    pub fn terminal_private(&self) -> Result<()> {
        self.validate_acl()?;
        let private = Self::private()?;
        if unsafe { EqualSid(self.owner()?, private.owner()?) } == 0 {
            return Err(Failure::new(
                "EACL",
                "Terminal journal owner is not the current user.",
            ));
        }
        let acl = self.dacl()?;
        for index in 0..unsafe { (*acl).AceCount } {
            let mut raw = null_mut();
            if unsafe { GetAce(acl, index as u32, &mut raw) } == 0 {
                return Err(failure());
            }
            let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
            if ![0, 1].contains(&ace.Header.AceType) {
                return Err(Failure::new("ENOTSUP", "Unsupported terminal journal ACE."));
            }
            if ace.Header.AceType == 0 {
                let sid = (&ace.SidStart as *const u32).cast_mut().cast();
                if unsafe { EqualSid(sid, private.owner()?) } == 0
                    && unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } == 0
                    && unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } == 0
                {
                    return Err(Failure::new(
                        "EACL",
                        "Terminal journal has a non-private access grant.",
                    ));
                }
            }
        }
        Ok(())
    }
    pub fn private() -> Result<Self> {
        Self::private_access("FA", "")
    }
    pub fn private_directory() -> Result<Self> {
        Self::private_access("FA", "OICI")
    }
    pub fn private_mutex() -> Result<Self> {
        Self::private_access("0x001f0001", "")
    }
    fn private_access(access: &str, inherit: &str) -> Result<Self> {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(failure());
        }
        let mut required = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut required);
        }
        let mut data = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                data.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        };
        unsafe {
            CloseHandle(token);
        }
        if ok == 0 {
            return Err(failure());
        }
        let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
        let mut text = null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(failure());
        }
        let mut length = 0;
        unsafe {
            while *text.add(length) != 0 {
                length += 1;
            }
        }
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        unsafe {
            LocalFree(text.cast());
        }
        let sddl: Vec<u16> =
            format!("O:{sid}D:P(A;{inherit};{access};;;{sid})(A;{inherit};{access};;;SY)")
                .encode_utf16()
                .chain(Some(0))
                .collect();
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(failure());
        }
        Ok(Self(descriptor))
    }

    pub fn read(file: &File) -> Result<Self> {
        let mut descriptor = null_mut();
        let code = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(Failure::new(
                "EACL",
                "Security descriptor could not be read.",
            ));
        }
        let result = Self(descriptor);
        result.validate_acl()?;
        Ok(result)
    }
    fn validate_acl(&self) -> Result<()> {
        // Reject absent/null DACLs and complex ACEs rather than widen permissions.
        let acl = self.dacl()?;
        for index in 0..unsafe { (*acl).AceCount } {
            let mut ace = null_mut();
            if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 {
                return Err(failure());
            }
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if ![0, 1].contains(&header.AceType) || header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
                return Err(Failure::new(
                    "ENOTSUP",
                    "Complex file security is unsupported.",
                ));
            }
        }
        Ok(())
    }

    fn dacl(&self) -> Result<*mut ACL> {
        let mut acl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted) } == 0
            || present == 0
            || acl.is_null()
        {
            return Err(Failure::new("EACL", "A non-null DACL is required."));
        }
        Ok(acl)
    }

    fn owner(&self) -> Result<PSID> {
        let mut sid = null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorOwner(self.0, &mut sid, &mut defaulted) } == 0
            || sid.is_null()
        {
            return Err(failure());
        }
        Ok(sid)
    }

    fn group(&self) -> Result<PSID> {
        let mut sid = null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorGroup(self.0, &mut sid, &mut defaulted) } == 0
            || sid.is_null()
        {
            return Err(failure());
        }
        Ok(sid)
    }

    fn control(&self) -> Result<u16> {
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(self.0, &mut control, &mut revision) } == 0 {
            return Err(failure());
        }
        Ok(control)
    }

    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    pub fn apply(&self, file: &File) -> Result<()> {
        // Apply to a same-directory temp, then require an exact owner/group/DACL
        // and inheritance-control match. Any inherited-ACE merge that changes the
        // original descriptor is refused before writing the body.
        // The APIs differ in automatic-inheritance bookkeeping: SetSecurityInfo
        // sets AUTO_INHERITED, SetKernelObjectSecurity clears it. Select from the
        // captured descriptor before applying; no retry or permission relaxation.
        if self.control()? & SE_DACL_AUTO_INHERITED == 0 {
            if unsafe {
                SetKernelObjectSecurity(
                    file.as_raw_handle(),
                    OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | if self.control()? & SE_DACL_PROTECTED != 0 {
                            PROTECTED_DACL_SECURITY_INFORMATION
                        } else {
                            UNPROTECTED_DACL_SECURITY_INFORMATION
                        },
                    self.0,
                )
            } == 0
            {
                return Err(failure());
            }
        } else if unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | if self.control()? & SE_DACL_PROTECTED != 0 {
                        PROTECTED_DACL_SECURITY_INFORMATION
                    } else {
                        UNPROTECTED_DACL_SECURITY_INFORMATION
                    },
                self.owner()?,
                self.group()?,
                self.dacl()?,
                null_mut(),
            )
        } != ERROR_SUCCESS
        {
            // SetSecurityInfo returns its own DWORD, not GetLastError.
            return Err(Failure::new("EACL", "File security could not be applied."));
        }
        self.matches(file, true)
    }

    pub fn matches(&self, file: &File, group: bool) -> Result<()> {
        let other = Self::read(file)?;
        let a = self.dacl()?;
        let b = other.dacl()?;
        let same_acl = unsafe {
            std::slice::from_raw_parts(a.cast::<u8>(), (*a).AclSize as usize)
                == std::slice::from_raw_parts(b.cast::<u8>(), (*b).AclSize as usize)
        };
        if !same_acl
            || unsafe { EqualSid(self.owner()?, other.owner()?) } == 0
            || (group && unsafe { EqualSid(self.group()?, other.group()?) } == 0)
            || (self.control()? & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED))
                != (other.control()? & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED))
        {
            return Err(Failure::new(
                "EACL",
                "File security does not match the required descriptor.",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod terminal_tests {
    use super::*;
    #[test]
    fn terminal_uses_production_acl_validation_without_applying_descriptors() {
        let current = Descriptor::private().unwrap();
        let mut raw_sid = null_mut();
        assert_ne!(
            unsafe { ConvertSidToStringSidW(current.owner().unwrap(), &mut raw_sid) },
            0
        );
        let mut length = 0;
        unsafe {
            while *raw_sid.add(length) != 0 {
                length += 1;
            }
        }
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw_sid, length) });
        unsafe {
            LocalFree(raw_sid.cast());
        }
        for (dacl, accepted) in [
            (format!("D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FR;;;BA)"), true),
            (format!("D:P(D;;FW;;;WD)(A;;FA;;;{sid})"), true),
            (format!("D:P(A;;FA;;;{sid})(A;;FR;;;WD)"), false),
            (
                format!("D:P(A;;FA;;;{sid})(XA;;FR;;;WD;(@User.Title == \"fixture\"))"),
                false,
            ),
            (format!("D:P(A;;FA;;;{sid})(OA;;FR;;;WD)"), false),
            ("D:NO_ACCESS_CONTROL".to_owned(), false),
            (String::new(), false),
        ] {
            let text: Vec<u16> = format!("O:{sid}{dacl}")
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut raw = null_mut();
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        text.as_ptr(),
                        1,
                        &mut raw,
                        null_mut(),
                    )
                },
                0
            );
            let descriptor = Descriptor(raw);
            // The same validator is called by Descriptor::read before any
            // journal decrypt. No descriptor is applied to a filesystem object.
            assert_eq!(descriptor.terminal_private().is_ok(), accepted, "{dacl}");
        }
    }
}
