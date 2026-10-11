use std::ffi::{OsStr, c_void};
use std::mem::zeroed;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{self, null, null_mut};

use bitflags::bitflags;
use anyhow::{Result, bail};
use windows_sys::core::w;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, FALSE, GetLastError, HANDLE, LUID, TRUE,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetSidSubAuthority, GetSidSubAuthorityCount,
    GetTokenInformation, LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NEW_CREDENTIALS,
    LOGON32_PROVIDER_DEFAULT, LOGON32_PROVIDER_WINNT50, LUID_AND_ATTRIBUTES, LogonUserW,
    LookupPrivilegeNameW, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_MANDATORY_LABEL,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TokenIntegrityLevel, TokenPrimary, TokenPrivileges,
};
use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};
use windows_sys::Win32::System::Environment::{
    CreateEnvironmentBlock, DestroyEnvironmentBlock, GetEnvironmentStringsW,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, DESKTOP_READ_CONTROL, DESKTOP_READOBJECTS,
    DESKTOP_WRITE_DAC, DESKTOP_WRITEOBJECTS, GetProcessWindowStation,
    GetUserObjectInformationW, OpenDesktopW, OpenWindowStationW, SetProcessWindowStation,
    UOI_NAME,
};
use windows_sys::Win32::System::SystemServices::{
    SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID,
    SECURITY_MANDATORY_SYSTEM_RID,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    CreateProcessWithLogonW, CreateProcessWithTokenW, LOGON_NETCREDENTIALS_ONLY,
    LOGON_WITH_PROFILE, OpenProcessToken, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

use crate::sid::get_user_sid;
use crate::acl::{Acl, Object};
use crate::pipe::{create_pipe, read_pipe};

bitflags! {
    /// Controls how credentials, profiles, and environment variables are applied.
    ///
    /// # Examples
    ///
    /// ```
    /// use runas_rs::Options;
    ///
    /// let options = Options::ENV | Options::PROFILE;
    /// assert!(options.contains(Options::ENV));
    /// assert!(options.contains(Options::PROFILE));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Options: u32 {
        /// Passes the current process environment to the child process.
        const ENV = 1 << 0;

        /// Starts the process without loading the target user's profile.
        const NO_PROFILE = 1 << 1;

        /// Loads the target user's profile before starting the process.
        const PROFILE = 1 << 2;

        /// Applies the supplied credentials only to outbound network access.
        const NET_ONLY = 1 << 3;
    }
}

/// Executes processes under alternate user credentials.
///
/// Handles authentication, window station/desktop ACL configuration, and
/// automatic selection of the appropriate process creation API based on
/// available privileges.
///
/// # Examples
///
/// Basic usage:
///
/// ```no_run
/// use runas_rs::Runas;
///
/// # fn main() -> anyhow::Result<()> {
/// let output = Runas::new("admin", "password", Some("DOMAIN"))
///     .run("cmd.exe /c whoami")?;
///
/// println!("{output}");
/// # Ok(())
/// # }
/// ```
///
/// With options:
///
/// ```no_run
/// use runas_rs::{Options, Runas};
///
/// # fn main() -> anyhow::Result<()> {
/// let output = Runas::new("admin", "password", None)
///     .options(Options::ENV | Options::PROFILE)?
///     .run("cmd.exe /c set")?;
/// # Ok(())
/// # }
/// ```
///
/// Network-only credentials:
///
/// ```no_run
/// use runas_rs::{Options, Runas};
///
/// # fn main() -> anyhow::Result<()> {
/// let output = Runas::new("admin", "password", Some("DOMAIN"))
///     .options(Options::NET_ONLY)?
///     .run("cmd.exe /c dir \\\\server\\share")?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runas<'a> {
    username: &'a str,
    password: &'a str,
    domain: &'a str,
    env: *mut c_void,
    logon_flags: u32,
    logon_type: u32,
    provider: u32,
    creation_flags: u32,
}

impl<'a> Runas<'a> {
    /// Creates an instance with the specified user credentials.
    ///
    /// An omitted domain is passed to Windows as an empty string.
    ///
    /// # Examples
    ///
    /// ```
    /// use runas_rs::Runas;
    ///
    /// let _runas = Runas::new("username", "password", Some("DOMAIN"));
    /// ```
    pub fn new(username: &'a str, password: &'a str, domain: Option<&'a str>) -> Self {
        Self {
            username,
            password,
            domain: domain.unwrap_or_default(),
            ..Default::default()
        }
    }

    /// Configures profile, environment, and credential behavior.
    ///
    /// `PROFILE` cannot be combined with `NO_PROFILE` or `NET_ONLY`.
    ///
    /// # Examples
    ///
    /// ```
    /// use runas_rs::{Options, Runas};
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// let _runas = Runas::new("username", "password", None)
    ///     .options(Options::ENV | Options::PROFILE)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn options(mut self, flags: Options) -> Result<Self> {
        if flags.contains(Options::PROFILE | Options::NO_PROFILE) {
            bail!("`/profile` is not compatible with `/noprofile`");
        }

        if flags.contains(Options::PROFILE | Options::NET_ONLY) {
            bail!("`/profile` is not compatible with `/netonly`");
        }

        if flags.contains(Options::PROFILE) {
            self.logon_flags = LOGON_WITH_PROFILE;
        } else if flags.contains(Options::NO_PROFILE) {
            self.logon_flags &= !LOGON_WITH_PROFILE;
        }

        if flags.contains(Options::NET_ONLY) {
            self.logon_flags |= LOGON_NETCREDENTIALS_ONLY;
            self.logon_type = LOGON32_LOGON_NEW_CREDENTIALS;
            self.provider = LOGON32_PROVIDER_WINNT50;
        }

        if flags.contains(Options::ENV) {
            self.env = unsafe { GetEnvironmentStringsW().cast() };
            self.creation_flags = CREATE_UNICODE_ENVIRONMENT;
        }

        Ok(self)
    }

    /// Runs a command as the configured user.
    ///
    /// Configures window station/desktop permissions, authenticates with the
    /// provided credentials, and executes the command. Returns the captured
    /// stdout/stderr output.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use runas_rs::Runas;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// let output = Runas::new("admin", "password", None)
    ///     .run("cmd.exe /c whoami /all")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn run(&mut self, command: &str) -> Result<String> {
        unsafe {
            let desktop = self.configure()?;
            let mut desktop_wide = desktop.as_str().to_wide();

            let (read, write) = create_pipe()?;
            let mut pi = zeroed::<PROCESS_INFORMATION>();
            let si = STARTUPINFOW {
                cb: size_of::<STARTUPINFOW>() as u32,
                lpDesktop: desktop_wide.as_mut_ptr(),
                hStdOutput: write,
                hStdError: write,
                dwFlags: STARTF_USESTDHANDLES,
                ..zeroed()
            };

            let username = self.username.to_wide();
            let domain = self.domain.to_wide();
            let password = self.password.to_wide();
            let mut command = command.to_wide();

            match self.select_creation_method()? {
                CreationMethod::AsUser => {
                    let mut h_token = null_mut();
                    if LogonUserW(
                        username.as_ptr(),
                        domain.as_ptr(),
                        password.as_ptr(),
                        self.logon_type,
                        self.provider,
                        &mut h_token
                    ) == FALSE 
                    {
                        bail!("LogonUserW Failed With Error [CreateProcessAsUser]: {}", GetLastError());
                    }

                    if let Err(e) = enable_privilege("SeAssignPrimaryTokenPrivilege") {
                        bail!("Error enabling privilege SeAssignPrimaryTokenPrivilege: {e}");
                    }

                    let mut h_duptoken = null_mut();
                    if DuplicateTokenEx(
                        h_token, 
                        TOKEN_ALL_ACCESS, 
                        null(), 
                        SecurityImpersonation, 
                        TokenPrimary, 
                        &mut h_duptoken
                    ) == FALSE 
                    {
                        bail!("DuplicateTokenEx Failed With Error [CreateProcessAsUser]: {}", GetLastError());
                    }

                    if self.env.is_null() 
                        && CreateEnvironmentBlock(&mut self.env, h_duptoken, FALSE) == FALSE 
                    {
                        bail!("CreateEnvironmentBlock Failed With Error: {}", GetLastError());
                    }

                    let dir = format!("{}\\System32", std::env::var("SystemRoot")?).as_str().to_wide();
                    if CreateProcessAsUserW(
                        h_duptoken,
                        null(),
                        command.as_mut_ptr(),
                        null_mut(),
                        null_mut(),
                        TRUE,
                        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                        self.env,
                        dir.as_ptr(),
                        &si,
                        &mut pi,
                    ) == FALSE
                    {
                        bail!("CreateProcessAsUserW Failed With Error: {}", GetLastError());
                    }
                }
                CreationMethod::WithToken => {
                    let mut h_token = null_mut();
                    if LogonUserW(
                        username.as_ptr(), 
                        domain.as_ptr(), 
                        password.as_ptr(), 
                        self.logon_type, 
                        self.provider, 
                        &mut h_token
                    ) == FALSE 
                    {
                        bail!("LogonUserW Failed With Error [CreateProcessWithToken]: {}", GetLastError());
                    }

                    if let Err(e) = enable_privilege("SeImpersonatePrivilege") {
                        bail!("Error enabling privilege SeImpersonatePrivilege: {e}");
                    }

                    let mut h_duptoken = null_mut();
                    if DuplicateTokenEx(
                        h_token, 
                        TOKEN_ALL_ACCESS, 
                        null(), 
                        SecurityImpersonation, 
                        TokenPrimary, 
                        &mut h_duptoken
                    ) == FALSE 
                    {
                        bail!("DuplicateTokenEx Failed With Error [CreateProcessWithToken]: {}", GetLastError());
                    }

                    if CreateProcessWithTokenW(
                        h_duptoken,
                        self.logon_flags,
                        null(),
                        command.as_mut_ptr(),
                        CREATE_NO_WINDOW | self.creation_flags,
                        self.env,
                        null_mut(),
                        &si,
                        &mut pi,
                    ) == FALSE
                    {
                        bail!("CreateProcessWithTokenW Failed With Error: {}", GetLastError());
                    }
                }
                CreationMethod::WithLogon => {
                    if CreateProcessWithLogonW(
                        username.as_ptr(),
                        domain.as_ptr(),
                        password.as_ptr(),
                        self.logon_flags,
                        null_mut(),
                        command.as_mut_ptr(),
                        CREATE_NO_WINDOW | self.creation_flags,
                        self.env,
                        null_mut(),
                        &si,
                        &mut pi,
                    ) == FALSE
                    {
                        bail!("CreateProcessWithLogonW Failed With Error: {}", GetLastError());
                    }
                }
            }

            CloseHandle(write);
            Ok(read_pipe(read))
        }
    }

    /// Grants the target user access to the current window station and desktop.
    ///
    /// Returns the fully qualified desktop name passed to the process creation API.
    fn configure(&self) -> Result<String> {
        let name = self.get_windows_station()?;
        let station_name = name.as_str().to_wide();
        unsafe {
            let old_hwinsta = GetProcessWindowStation();

            let h_winsta = OpenWindowStationW(station_name.as_ptr(), FALSE, READ_CONTROL | WRITE_DAC);
            if h_winsta.is_null() {
                bail!("OpenWindowStationW Failed With Error: {}", GetLastError());
            }

            SetProcessWindowStation(h_winsta);

            // OpenDesktopW resolves the desktop against the process window station.
            let h_desktop = OpenDesktopW(
                w!("Default"),
                0,
                FALSE,
                DESKTOP_READ_CONTROL
                    | DESKTOP_WRITE_DAC
                    | DESKTOP_WRITEOBJECTS
                    | DESKTOP_READOBJECTS,
            );

            if h_desktop.is_null() {
                bail!("OpenDesktopW Failed With Error: {}", GetLastError());
            }

            SetProcessWindowStation(old_hwinsta);

            let mut user_sid = get_user_sid(self.username, self.domain)?;

            let mut acl_station = Acl::new(h_winsta, &mut user_sid, Object::WindowsStation);
            if !acl_station.check_permissions()? {
                acl_station.add_ace()?;
            }

            let mut acl_desktop = Acl::new(h_desktop, &mut user_sid, Object::Desktop);
            if !acl_desktop.check_permissions()? {
                acl_desktop.add_ace()?;
            }

            CloseWindowStation(h_winsta);
            CloseDesktop(h_desktop);

            Ok(format!("{name}\\Default"))
        }
    }

    /// Selects the process creation API supported by the caller's token.
    ///
    /// - `CreateProcessAsUserW` requires `SeAssignPrimaryTokenPrivilege` and
    ///   medium, high, or system integrity.
    /// - `CreateProcessWithTokenW` requires `SeImpersonatePrivilege` and high
    ///   or system integrity.
    /// - `CreateProcessWithLogonW` is used when neither privileged path is
    ///   available.
    fn select_creation_method(&self) -> Result<CreationMethod> {
        let integrity = integrity_level()?;
        let se_impersonate = has_privilege("SeImpersonatePrivilege")?;
        let se_assign = has_privilege("SeAssignPrimaryTokenPrivilege")?;

        if se_assign && matches!(integrity, "Medium" | "High" | "System") {
            Ok(CreationMethod::AsUser)
        } else if se_impersonate && matches!(integrity, "High" | "System") {
            Ok(CreationMethod::WithToken)
        } else {
            Ok(CreationMethod::WithLogon)
        }
    }

    /// Returns the name of the current window station.
    fn get_windows_station(&self) -> Result<String> {
        let h_winsta = unsafe { GetProcessWindowStation() };
        if h_winsta.is_null() {
            bail!("GetProcessWindowStation Failed With Error: {}", unsafe { GetLastError() });
        }

        let mut buffer = vec![0u16; 256];
        let mut len = 0;
        if unsafe { 
            GetUserObjectInformationW(
                h_winsta,
                UOI_NAME,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 2) as u32,
                &mut len,
            )
        } == FALSE 
        {
            bail!("GetUserObjectInformationW Failed With Error: {}", unsafe { GetLastError() });
        }

        let len = (len / 2) as usize - 1;
        buffer.truncate(len);

        Ok(String::from_utf16_lossy(&buffer))
    }
}

impl Default for Runas<'_> {
    fn default() -> Self {
        Self {
            username: "",
            password: "",
            domain: ".",
            env: null_mut(),
            logon_flags: 0,
            creation_flags: 0,
            logon_type: LOGON32_LOGON_INTERACTIVE,
            provider: LOGON32_PROVIDER_DEFAULT,
        }
    }
}

impl Drop for Runas<'_> {
    fn drop(&mut self) {
        if !self.env.is_null() {
            unsafe { DestroyEnvironmentBlock(self.env) };
        }
    }
}

/// Windows API used to create the child process.
#[derive(Debug, Clone, Copy)]
enum CreationMethod {
    /// Creates the process from a primary token with `CreateProcessAsUserW`.
    AsUser,
    /// Creates the process from a token with `CreateProcessWithTokenW`.
    WithToken,
    /// Creates the process directly from credentials with `CreateProcessWithLogonW`.
    WithLogon,
}

/// Returns the caller token's integrity level as a display label.
fn integrity_level() -> Result<&'static str> {
    unsafe {
        let mut h_token = null_mut();
        if OpenProcessToken(-1isize as HANDLE, TOKEN_QUERY, &mut h_token) == FALSE {
            bail!("GetProcessWindowStation Failed With Error: {}", GetLastError());
        }

        // Windows reports the required buffer length through the first call.
        let mut len = 0;
        GetTokenInformation(h_token, TokenIntegrityLevel, null_mut(), 0, &mut len);
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            bail!("GetTokenInformation Failed With Error: {}", GetLastError());
        }

        let mut buffer = vec![0u8; len as usize];
        if GetTokenInformation(
            h_token,
            TokenIntegrityLevel,
            buffer.as_mut_ptr().cast(),
            len, &mut len,
        ) == FALSE
        {
            bail!("GetTokenInformation [2] Failed With Error: {}", GetLastError());
        }

        let til = buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL;
        let count = GetSidSubAuthorityCount((*til).Label.Sid);
        if count.is_null() {
            bail!("GetSidSubAuthorityCount Failed With Error: {}", GetLastError());
        }

        // The last SID sub-authority contains the mandatory integrity RID.
        let ptr = GetSidSubAuthority((*til).Label.Sid, (*count - 1) as u32);
        if ptr.is_null() {
            bail!("GetSidSubAuthority Failed With Error: {}", GetLastError());
        }

        let level = ptr::read(ptr) as i32;
        let label = match level {
            SECURITY_MANDATORY_LOW_RID => "Low",
            SECURITY_MANDATORY_MEDIUM_RID => "Medium",
            SECURITY_MANDATORY_HIGH_RID => "High",
            SECURITY_MANDATORY_SYSTEM_RID => "System",
            _ => "Unknown",
        };

        Ok(label)
    }
}

/// Reports whether the caller token contains the named privilege.
fn has_privilege(name: &str) -> Result<bool> {
    unsafe {
        let mut h_token = null_mut();
        if OpenProcessToken(-1isize as HANDLE, TOKEN_QUERY, &mut h_token) == FALSE {
            bail!("OpenProcessToken Failed With Error: {}", GetLastError());
        }

        // Windows reports the required buffer length through the first call.
        let mut len = 0;
        GetTokenInformation(h_token, TokenPrivileges, null_mut(), 0, &mut len);
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            bail!("GetTokenInformation Failed With Error: {}", GetLastError());
        }

        let mut buffer = vec![0u8; len as usize];
        if GetTokenInformation(
            h_token,
            TokenPrivileges,
            buffer.as_mut_ptr().cast(),
            len,
            &mut len,
        ) == FALSE
        {
            bail!("GetTokenInformation [2] Failed With Error: {}", GetLastError());
        }

        let header = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
        let privs = &header.Privileges as *const LUID_AND_ATTRIBUTES;
        for i in 0..header.PrivilegeCount {
            let luid_attr = privs.add(i as usize);
            let luid = (*luid_attr).Luid;

            let mut buffer = vec![0u16; 128];
            let mut len = buffer.len() as u32;

            if LookupPrivilegeNameW(null(), &luid, buffer.as_mut_ptr(), &mut len) == FALSE {
                continue;
            }

            buffer.truncate(len as usize);
            let privilege = String::from_utf16_lossy(&buffer);

            if privilege == name {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Enables the named privilege in the caller token.
fn enable_privilege(name: &str) -> Result<()> {
    unsafe {
        let mut h_token = null_mut();
        if OpenProcessToken(
            -1isize as HANDLE,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut h_token,
        ) == FALSE
        {
            bail!("OpenProcessToken Failed With Error: {}", GetLastError());
        }

        let mut token_priv = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: zeroed(),
                Attributes: SE_PRIVILEGE_ENABLED,
            }; 1],
        };

        if LookupPrivilegeValueW(
            null_mut(),
            name.to_wide().as_ptr(),
            &mut token_priv.Privileges[0].Luid as *mut LUID,
        ) == FALSE
        {
            bail!("LookupPrivilegeValueW Failed With Error: {}", GetLastError());
        }

        if AdjustTokenPrivileges(h_token, 0, &token_priv, 0, null_mut(), null_mut()) == FALSE {
            bail!("AdjustTokenPrivileges Failed With Error: {}", GetLastError());
        }
    }

    Ok(())
}

/// Converts Rust strings into null-terminated UTF-16 buffers for Win32 APIs.
trait ToWide {
    fn to_wide(&self) -> Vec<u16>;
}

impl ToWide for &str {
    fn to_wide(&self) -> Vec<u16> {
        OsStr::new(self)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}
