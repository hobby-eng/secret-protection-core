//! Metadata read from a fresh AppContainer when strict admission fails in native CI.
use std::mem::size_of;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenIntegrityLevel,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

pub(super) fn token_metadata() -> String {
    let mut primary: HANDLE = ptr::null_mut();
    let mut effective: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo handles are borrowed. Each successful open returns a token
    // owned by this call, and both output slots are writable.
    let (primary_error, effective_error) = unsafe {
        let p = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut primary);
        let first = if p == 0 { Some(GetLastError()) } else { None };
        let t = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut effective);
        (first, if t == 0 { Some(GetLastError()) } else { None })
    };
    let mut label = [0usize; 32];
    let mut used = 0;
    // SAFETY: the aligned token buffer contains the label and SID on success. All
    // accesses happen while its storage is live. Only the integrity RID is reported.
    let rid = unsafe {
        if !primary.is_null()
            && GetTokenInformation(
                primary,
                TokenIntegrityLevel,
                label.as_mut_ptr().cast(),
                size_of_val(&label) as u32,
                &mut used,
            ) != 0
            && used as usize >= size_of::<TOKEN_MANDATORY_LABEL>()
        {
            let sid = (*label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
            u32::from(*GetSidSubAuthorityCount(sid))
                .checked_sub(1)
                .map(|index| *GetSidSubAuthority(sid, index))
        } else {
            None
        }
    };
    for h in [primary, effective] {
        if !h.is_null() {
            // SAFETY: each nonnull handle was acquired above and is closed exactly once.
            unsafe { CloseHandle(h) };
        }
    }
    format!(
        "primary open error={primary_error:?}, primary RID={rid:?}, caller token error={effective_error:?}"
    )
}
