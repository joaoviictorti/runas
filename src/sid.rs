use std::ffi::CString;
use std::ptr::null_mut;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{FALSE, GetLastError};
use windows_sys::Win32::Security::{LookupAccountNameA, SID_NAME_USE};

/// Resolves the binary SID for a local or domain account.
///
/// A non-empty domain produces a `domain\\username` lookup; an empty domain or
/// `.` resolves the username directly.
pub fn get_user_sid(username: &str, domain: &str) -> Result<Vec<u8>> {
    let full_account_name = if !domain.is_empty() && domain != "." {
        format!("{}\\{}", domain, username)
    } else {
        username.to_string()
    };

    let faqn = CString::new(full_account_name)?;
    let sid = null_mut();
    let mut cbsid = 0;
    let mut len = 0;
    let mut sid_name = SID_NAME_USE::default();

    unsafe {
        // LookupAccountNameA reports both required buffer lengths on this call.
        LookupAccountNameA(
            null_mut(),
            faqn.as_ptr().cast(),
            sid,
            &mut cbsid,
            null_mut(),
            &mut len,
            &mut sid_name,
        );

        let mut sid = vec![0u8; cbsid as usize];
        let mut domain_buffer = vec![0u8; len as usize];
        if LookupAccountNameA(
            null_mut(),
            faqn.as_ptr().cast(),
            sid.as_mut_ptr().cast(),
            &mut cbsid,
            domain_buffer.as_mut_ptr(),
            &mut len,
            &mut sid_name,
        ) == FALSE
        {
            bail!("LookupAccountNameA Failed With Error: {}", GetLastError());
        }

        Ok(sid)
    }
}
