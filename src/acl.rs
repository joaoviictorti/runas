use std::ffi::c_void;
use std::mem::zeroed;
use std::ptr::null_mut;

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::{
    FALSE, GetLastError, GENERIC_ALL, TRUE
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER
};
use windows_sys::Win32::System::StationsAndDesktops::{
    DESKTOP_CREATEMENU, DESKTOP_CREATEWINDOW, DESKTOP_ENUMERATE,
    DESKTOP_HOOKCONTROL, DESKTOP_JOURNALPLAYBACK, DESKTOP_JOURNALRECORD,
    DESKTOP_READOBJECTS, DESKTOP_SWITCHDESKTOP, DESKTOP_WRITEOBJECTS,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    WINSTA_ACCESSCLIPBOARD, WINSTA_ACCESSGLOBALATOMS, WINSTA_CREATEDESKTOP,
    WINSTA_ENUMDESKTOPS, WINSTA_ENUMERATE, WINSTA_EXITWINDOWS,
    WINSTA_READATTRIBUTES, WINSTA_READSCREEN, WINSTA_WRITEATTRIBUTES,
};
use windows_sys::Win32::Security::{
    AddAccessAllowedAce, AddAccessAllowedAceEx, AddAce, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorDacl, GetUserObjectSecurity, InitializeAcl, InitializeSecurityDescriptor,
    SetSecurityDescriptorDacl, SetUserObjectSecurity, ACE_HEADER, ACCESS_ALLOWED_ACE, ACL,
    ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE,
    SECURITY_DESCRIPTOR,
};

/// Standard rights included in each full-access mask.
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;

/// Rights granted to the target SID on a desktop.
const DESKTOP_ALL: u32 = DESKTOP_READOBJECTS
    | DESKTOP_CREATEWINDOW
    | DESKTOP_CREATEMENU
    | DESKTOP_HOOKCONTROL
    | DESKTOP_JOURNALRECORD
    | DESKTOP_JOURNALPLAYBACK
    | DESKTOP_ENUMERATE
    | DESKTOP_WRITEOBJECTS
    | DESKTOP_SWITCHDESKTOP
    | STANDARD_RIGHTS_REQUIRED;

/// Rights granted to the target SID on a window station.
const WINSTA_ALL: u32 = (WINSTA_ACCESSCLIPBOARD
    | WINSTA_ACCESSGLOBALATOMS
    | WINSTA_CREATEDESKTOP
    | WINSTA_ENUMDESKTOPS
    | WINSTA_ENUMERATE
    | WINSTA_EXITWINDOWS
    | WINSTA_READATTRIBUTES
    | WINSTA_READSCREEN
    | WINSTA_WRITEATTRIBUTES
    | DELETE as i32
    | READ_CONTROL as i32
    | WRITE_DAC as i32
    | WRITE_OWNER as i32) as u32;

/// User object whose discretionary access control list is being managed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    /// A window station containing one or more desktops.
    WindowsStation,
    /// A desktop that receives user interface objects.
    Desktop,
}

/// Manages the access entries required by a user SID on a Windows user object.
///
/// Existing entries are retained when new permissions are added.
pub struct Acl<'a> {
    h_object: *mut c_void,
    sid: &'a mut Vec<u8>,
    object: Object,
}

impl<'a> Acl<'a> {
    /// Associates a user-object handle and SID with the requested object type.
    pub fn new(h_object: *mut c_void, sid: &'a mut Vec<u8>, object: Object) -> Self {
        Self { h_object, sid, object }
    }

    /// Adds the access entries required by the configured SID.
    ///
    /// A window station receives an inheritable entry and a station-level
    /// entry. A desktop receives one entry containing the desktop access mask.
    pub fn add_ace(&mut self) -> Result<()> {
        unsafe {
            // Query once to obtain the security descriptor buffer length.
            let mut len = 0;
            let requested = DACL_SECURITY_INFORMATION;
            GetUserObjectSecurity(self.h_object, &requested, null_mut(), 0, &mut len);

            let mut psid = vec![0u8; len as usize];
            if GetUserObjectSecurity(
                self.h_object, 
                &requested, 
                psid.as_mut_ptr().cast(), 
                len, 
                &mut len
            ) == FALSE 
            {
                bail!("failed to get user object security (error {})", GetLastError());
            }

            let mut dacl = zeroed();
            let mut dacl_exist = 0;
            let mut dacl_present = 0;
            if GetSecurityDescriptorDacl(
                psid.as_mut_ptr().cast(), 
                &mut dacl_present, 
                &mut dacl, 
                &mut dacl_exist
            ) == FALSE 
            {
                bail!("failed to get security descriptor DACL (error {})", GetLastError());
            }

            let mut acl_info = zeroed::<ACL_SIZE_INFORMATION>();
            if GetAclInformation(
                dacl,
                (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ) == FALSE
            {
                bail!("failed to get ACL information (error {})", GetLastError());
            }

            let mut security_descriptor = zeroed::<SECURITY_DESCRIPTOR>();
            if InitializeSecurityDescriptor(
                (&mut security_descriptor as *mut SECURITY_DESCRIPTOR).cast::<c_void>(), 
                1,
            ) == FALSE 
            {
                bail!("failed to initialize security descriptor (error {})", GetLastError());
            }

            let new_size_ace = size_of::<ACCESS_ALLOWED_ACE>() + self.sid.len() - size_of::<u32>();
            let new_size_acl = if acl_info.AclBytesInUse == 0 {
                (size_of::<ACL>() + (new_size_ace * 2)) as u32
            } else {
                acl_info.AclBytesInUse + (new_size_ace * 2) as u32
            };

            let mut new_dacl_buffer = vec![0u8; new_size_acl as usize];
            let new_dacl = new_dacl_buffer.as_mut_ptr() as *mut ACL;
            if InitializeAcl(new_dacl, new_size_acl, ACL_REVISION) == FALSE {
                bail!("failed to initialize ACL (error {})", GetLastError());
            }

            // Preserve the original entries before appending the required ones.
            if dacl_present != 0 {
                for i in 0..acl_info.AceCount {
                    let mut ace = null_mut();
                    if GetAce(dacl, i, &mut ace) == FALSE {
                        bail!("failed to get ACE (error {})", GetLastError());
                    }

                    let ace_header = ace as *mut ACE_HEADER;
                    if AddAce(new_dacl, ACL_REVISION, u32::MAX, ace, (*ace_header).AceSize as u32) == FALSE {
                        bail!("failed to add existing ACE (error {})", GetLastError());
                    }
                }
            }

            match self.object {
                Object::WindowsStation => {
                    if AddAccessAllowedAceEx(
                        new_dacl,
                        ACL_REVISION,
                        CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE,
                        GENERIC_ALL,
                        self.sid.as_mut_ptr().cast(),
                    ) == FALSE
                    {
                        bail!("failed to add ACE to Windows Station (error {})", GetLastError());
                    }

                    if AddAccessAllowedAceEx(
                        new_dacl, 
                        ACL_REVISION, 
                        NO_PROPAGATE_INHERIT_ACE, 
                        WINSTA_ALL, 
                        self.sid.as_mut_ptr().cast()
                    ) == FALSE 
                    {
                        bail!("failed to add non-propagating ACE to Windows Station (error {})", GetLastError());
                    }
                }
                Object::Desktop => {
                    if AddAccessAllowedAce(
                        new_dacl, 
                        ACL_REVISION, 
                        DESKTOP_ALL, 
                        self.sid.as_mut_ptr().cast()
                    ) == FALSE 
                    {
                        bail!("failed to add ACE to Desktop (error {})", GetLastError());
                    }
                }
            }

            if SetSecurityDescriptorDacl(
                (&mut security_descriptor as *mut SECURITY_DESCRIPTOR).cast::<c_void>(), 
                TRUE, 
                new_dacl, 
                FALSE
            ) == FALSE 
            {
                bail!("failed to set security descriptor DACL (error {})", GetLastError());
            }

            if SetUserObjectSecurity(
                self.h_object, 
                &requested, 
                (&mut security_descriptor as *mut SECURITY_DESCRIPTOR).cast::<c_void>()
            ) == FALSE 
            {
                bail!("failed to set user object security (error {})", GetLastError());
            }

            Ok(())
        }
    }

    /// Reports whether the SID already has every required access entry.
    ///
    /// Window stations require both the inheritable and station-level entries;
    /// desktops require the desktop access mask.
    pub fn check_permissions(&mut self) -> Result<bool> {
        unsafe {
            // Query once to obtain the security descriptor buffer length.
            let mut len = 0;
            let requested = DACL_SECURITY_INFORMATION;
            GetUserObjectSecurity(self.h_object, &requested, null_mut(), 0, &mut len);

            let mut psid = vec![0u8; len as usize];
            if GetUserObjectSecurity(
                self.h_object, 
                &requested, 
                psid.as_mut_ptr().cast(), 
                len, 
                &mut len
            ) == FALSE 
            {
                bail!("failed to get user object security (error {})", GetLastError());
            }

            let mut dacl = zeroed();
            let mut dacl_exist = 0;
            let mut dacl_present = 0;
            if GetSecurityDescriptorDacl(
                psid.as_mut_ptr().cast(), 
                &mut dacl_present, 
                &mut dacl, 
                &mut dacl_exist
            ) == FALSE 
            {
                bail!("failed to get security descriptor DACL (error {})", GetLastError());
            }

            let mut acl_info = zeroed::<ACL_SIZE_INFORMATION>();
            if GetAclInformation(
                dacl,
                (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ) == FALSE
            {
                bail!("failed to get ACL information (error {})", GetLastError());
            }

            let mut ace_win_inherit = false;
            let mut ace_win_nonprop = false;
            let mut ace_desktop = false;

            if dacl_present != 0 {
                for i in 0..acl_info.AceCount {
                    let mut ace = null_mut();
                    if GetAce(dacl, i, &mut ace) == FALSE {
                        bail!("failed to get ACE (error {})", GetLastError());
                    }

                    let ace_header = ace as *mut ACE_HEADER;
                    if (*ace_header).AceType == 0 {
                        let ace = ace as *mut ACCESS_ALLOWED_ACE;
                        let ace_sid = (&mut (*ace).SidStart as *mut u32).cast::<c_void>();

                        if EqualSid(ace_sid, self.sid.as_mut_ptr().cast()) != FALSE {
                            let mask = (*ace).Mask;
                            let flags = (*ace).Header.AceFlags as u32;

                            match self.object {
                                Object::WindowsStation => {
                                    if mask == GENERIC_ALL && flags & 
                                        (CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE) != 0 
                                    {
                                        ace_win_inherit = true;
                                    }

                                    if mask == WINSTA_ALL && flags & NO_PROPAGATE_INHERIT_ACE != 0 {
                                        ace_win_nonprop = true;
                                    }
                                }
                                Object::Desktop => {
                                    if mask == DESKTOP_ALL {
                                        ace_desktop = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Ok(match self.object {
                Object::WindowsStation => ace_win_inherit && ace_win_nonprop,
                Object::Desktop => ace_desktop,
            })
        }
    }
}
