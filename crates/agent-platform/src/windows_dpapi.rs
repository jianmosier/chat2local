//! Current-user DPAPI only. The caller owns its format and output-size policy.
use chat2local_protocol::{Failure, Result};
use std::ptr::{null, null_mut};
use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};

struct Blob(CRYPT_INTEGER_BLOB);
impl Drop for Blob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            unsafe {
                LocalFree(self.0.pbData.cast());
            }
        }
    }
}
pub fn current_user_data(input: &[u8], protect: bool, output_limit: usize) -> Result<Vec<u8>> {
    let fail = || Failure::new("EDPAPI", "Current-user DPAPI operation failed.");
    let source = CRYPT_INTEGER_BLOB {
        cbData: input.len().try_into().map_err(|_| fail())?,
        pbData: input.as_ptr().cast_mut(),
    };
    let mut output = Blob(unsafe { std::mem::zeroed() });
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &source,
                null(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &source,
                null_mut(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    };
    if ok == 0 || output.0.pbData.is_null() || output.0.cbData as usize > output_limit {
        return Err(fail());
    }
    Ok(unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) }.to_vec())
}
