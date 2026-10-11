use std::ptr::null_mut;

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{FALSE, HANDLE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Pipes::CreatePipe;

/// Creates an inheritable anonymous pipe.
///
/// The returned tuple contains the read handle followed by the write handle.
pub fn create_pipe() -> Result<(HANDLE, HANDLE)> {
    unsafe {
        let mut h_read = null_mut();
        let mut h_write = null_mut();
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: 1,
            lpSecurityDescriptor: null_mut(),
        };

        if CreatePipe(&mut h_read, &mut h_write, &sa, 0) == 0 {
            bail!("error creating the pipe");
        }

        Ok((h_read, h_write))
    }
}

/// Reads the pipe until its writer closes and converts the bytes with UTF-8
/// replacement for invalid sequences.
pub fn read_pipe(h_read: HANDLE) -> String {
    let mut buffer = [0u8; 1 << 12];
    let mut bytes_read = 0;
    let mut output = String::new();

    unsafe {
        while ReadFile(
            h_read, 
            buffer.as_mut_ptr(), 
            buffer.len() as u32, 
            &mut bytes_read, 
            null_mut()
        ) != FALSE 
        {
            output.push_str(&String::from_utf8_lossy(&buffer[..bytes_read as usize]));
        }
    }

    output
}
