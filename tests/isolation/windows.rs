//! What Windows shows of an isolated process from outside.

use std::mem::size_of;

use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_NOT_ALL_ASSIGNED,
    ERROR_SUCCESS, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME,
    SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread, PROCESS_VM_READ,
    THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME,
};

/// A program of the same user can open the isolated process neither to read its memory nor
/// to change its access list, and none of its threads to read or change its context, suspend
/// it or change its access list; it can still read a thread's basic information.
pub(super) fn cannot_be_opened(pid: u32) {
    drop_debug_privilege();
    // SAFETY: each call opens the process object of the child, inheriting no handle.
    expect_refused(
        "the process",
        &[PROCESS_VM_READ, WRITE_DAC],
        |access| unsafe { OpenProcess(access, 0, pid) },
    );
    // SAFETY: takes a snapshot of the threads of the system, closed below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    assert_ne!(snapshot, INVALID_HANDLE_VALUE);
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    let mut threads = 0;
    // SAFETY: fills `entry`, whose size it names, from the snapshot.
    let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid && thread_cannot_be_opened(entry.th32ThreadID) {
            threads += 1;
        }
        // SAFETY: as above.
        more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    // SAFETY: closes the snapshot taken above, once.
    unsafe { CloseHandle(snapshot) };
    // The main thread and the two it started; Windows may have started more.
    assert!(threads >= 3, "{threads} threads");
}

/// Removes the debug privilege from this test's own token. A program that holds it opens every
/// process and thread whatever its access list, which the isolation does not cover, and the
/// test runner of a CI machine may hold it.
fn drop_debug_privilege() {
    let mut token = ptr::null_mut();
    // SAFETY: opens the token of this process to change its privileges; closed below.
    let opened =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) };
    assert_ne!(opened, 0);
    let mut privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: LUID::default(),
            Attributes: SE_PRIVILEGE_REMOVED,
        }],
    };
    // SAFETY: the name is NUL-terminated; the call writes the privilege's number.
    let found = unsafe {
        LookupPrivilegeValueW(
            ptr::null(),
            SE_DEBUG_NAME,
            &mut privileges.Privileges[0].Luid,
        )
    };
    assert_ne!(found, 0);
    // SAFETY: the list lives for the call, which is asked for no earlier state.
    let adjusted = unsafe {
        AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut())
    };
    // SAFETY: reads this thread's last error, which AdjustTokenPrivileges set.
    let error = unsafe { GetLastError() };
    // SAFETY: closes the token opened above, once.
    unsafe { CloseHandle(token) };
    // ERROR_NOT_ALL_ASSIGNED: the token does not hold the privilege.
    assert!(
        adjusted != 0 && matches!(error, ERROR_SUCCESS | ERROR_NOT_ALL_ASSIGNED),
        "error {error}"
    );
}

/// Checks the thread numbered `id`, and returns false for one that has ended since the
/// snapshot.
fn thread_cannot_be_opened(id: u32) -> bool {
    // SAFETY: opens the thread object, inheriting no handle; it stays open until the checks
    // end, so that its number names the same thread.
    let thread = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, id) };
    // SAFETY: reads this thread's last error, which OpenThread set.
    let error = unsafe { GetLastError() };
    if thread.is_null() && error == ERROR_INVALID_PARAMETER {
        return false;
    }
    assert!(!thread.is_null(), "thread {id}: error {error}");
    let refused_rights = [
        THREAD_GET_CONTEXT,
        THREAD_SET_CONTEXT,
        THREAD_SUSPEND_RESUME,
        WRITE_DAC,
    ];
    // SAFETY: each call opens the thread object, inheriting no handle.
    expect_refused(&format!("thread {id}"), &refused_rights, |access| unsafe {
        OpenThread(access, 0, id)
    });
    // SAFETY: closes the handle opened above, once.
    unsafe { CloseHandle(thread) };
    true
}

/// `open` refuses each of `rights` to `object` with ERROR_ACCESS_DENIED.
fn expect_refused(object: &str, rights: &[u32], open: impl Fn(u32) -> HANDLE) {
    for &access in rights {
        let handle = open(access);
        // SAFETY: reads this thread's last error, which `open` set.
        let error = unsafe { GetLastError() };
        if !handle.is_null() {
            // SAFETY: closes the handle just opened, once.
            unsafe { CloseHandle(handle) };
        }
        assert!(
            handle.is_null() && error == ERROR_ACCESS_DENIED,
            "{object}, access {access:#x}: error {error}"
        );
    }
}

/// Run in its own test child. One sibling impersonates itself while the calling thread lowers
/// the primary token. Only token metadata is read.
pub(super) fn an_impersonating_sibling_keeps_its_own_integrity() {
    use secret_protection_core::{Isolation, Protection};
    use std::os::windows::io::AsRawHandle;
    use std::sync::mpsc;
    use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};

    const LOW_RID: u32 = 4096;
    let primary = query_own_token(false);
    if token_label_rid(primary.as_raw_handle().cast()) <= LOW_RID {
        super::support::skip_role("the test needs a primary token above low integrity");
    }
    let (ready, has_token) = mpsc::sync_channel(0);
    let (finish, may_revert) = mpsc::channel();
    let sibling = std::thread::spawn(move || {
        // SAFETY: duplicates this test process's own token on this thread, for this scope.
        assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
        let token = query_own_token(true);
        ready
            .send(token_label_rid(token.as_raw_handle().cast()))
            .unwrap();
        may_revert.recv().unwrap();
        // Query the effective token again instead of assuming it is still the same object.
        let effective = query_own_token(true);
        let observed = token_label_rid(effective.as_raw_handle().cast());
        // SAFETY: this thread established impersonation above.
        assert_ne!(unsafe { RevertToSelf() }, 0);
        observed
    });
    assert!(has_token.recv().unwrap() > LOW_RID);
    let report = Isolation::enter();
    finish.send(()).unwrap();
    let sibling_rid = sibling.join().unwrap();
    assert!(token_label_rid(primary.as_raw_handle().cast()) <= LOW_RID);
    assert!(sibling_rid > LOW_RID);
    assert!(!report.low_integrity);
    assert!(report.require(&[Protection::LowIntegrity]).is_err());
}

pub(super) fn primary_is_low() -> bool {
    use std::os::windows::io::AsRawHandle;
    token_label_rid(query_own_token(false).as_raw_handle().cast()) <= 4096
}

fn query_own_token(impersonating: bool) -> std::os::windows::io::OwnedHandle {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    let mut handle = ptr::null_mut();
    // SAFETY: opens the running thread or its process for a metadata-only query and writes
    // one owned handle on success. The impersonating sibling uses its own effective identity.
    let opened = unsafe {
        if impersonating {
            OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut handle)
        } else {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle)
        }
    };
    assert_ne!(opened, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: token acquisition succeeded and the handle has no other owner.
    unsafe { OwnedHandle::from_raw_handle(handle.cast()) }
}

fn token_label_rid(token: HANDLE) -> u32 {
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_MANDATORY_LABEL,
        TokenIntegrityLevel,
    };

    let mut storage = [0usize; 32];
    let mut count = 0;
    // SAFETY: the OS receives a pointer-aligned writable buffer and its exact byte count.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            storage.as_mut_ptr().cast(),
            std::mem::size_of_val(&storage) as u32,
            &mut count,
        )
    };
    assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
    assert!(count as usize >= size_of::<TOKEN_MANDATORY_LABEL>());
    // SAFETY: the kernel returned a TOKEN_MANDATORY_LABEL referring to its SID in storage.
    unsafe {
        let sid = (*storage.as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
            .Label
            .Sid;
        let last = u32::from(*GetSidSubAuthorityCount(sid))
            .checked_sub(1)
            .unwrap();
        *GetSidSubAuthority(sid, last)
    }
}
