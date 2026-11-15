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
