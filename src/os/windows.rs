//! Secret pages on Windows: committed with `VirtualAlloc`, locked with `VirtualLock` once the
//! working set has room for them, and left out of Windows Error Reporting dumps. The work area of
//! a computation is such a region too. Also the protections of [`crate::protect::Isolation::enter`],
//! each for the whole process, and the secret writer.
#![allow(
    unsafe_code,
    reason = "the memory, error-reporting, security, thread and console calls of Windows are \
              foreign functions"
)]

use std::io;
use std::mem::size_of;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::Once;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, ERROR_SUCCESS, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree, S_OK,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid, GetSecurityDescriptorDacl,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, SID_AND_ATTRIBUTES, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TokenCapabilities, TokenDefaultDacl, TokenIntegrityLevel, TokenIsAppContainer,
};
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_OUTPUT_HANDLE, WriteConsoleW,
};
use windows_sys::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::ErrorReporting::{
    WER_FAULT_REPORTING_FLAG_NOHEAP, WerRegisterExcludedMemoryBlock, WerSetFlags,
    WerUnregisterExcludedMemoryBlock,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JobObjectBasicLimitInformation, JobObjectBasicUIRestrictions, SetInformationJobObject,
};
use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};
use windows_sys::Win32::System::Memory::{
    GetProcessWorkingSetSizeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS,
    PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, SetProcessWorkingSetSizeEx, VirtualAlloc,
    VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessIdOfThread, GetProcessMitigationPolicy,
    OpenProcessToken, OpenThread, PROCESS_MITIGATION_POLICY, ProcessChildProcessPolicy,
    ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
    ProcessSideChannelIsolationPolicy, ProcessSignaturePolicy, SetProcessMitigationPolicy,
};
use windows_sys::core::{PCWSTR, w};

use super::{Access, Pages, Region};
use crate::protect::{Isolation, Options, Secret};

/// What the working set grows by, once, so that the secrets of a process fit into what Windows
/// lets it lock: a process may lock little more than its minimum working set.
const WORKING_SET_RAISE: usize = 1 << 20;
/// The largest block one registration leaves out of error reports: its size is a 32-bit value.
const REPORT_BLOCK: usize = u32::MAX as usize;

static WORKING_SET_RAISED: Once = Once::new();

impl Pages {
    /// `bytes` bytes, at least one, in pages of their own.
    pub(crate) fn new(bytes: usize) -> Self {
        let start = commit(bytes).unwrap_or_else(|| super::out_of_memory(bytes));
        WORKING_SET_RAISED.call_once(|| {
            move_working_set(WORKING_SET_RAISE.cast_signed());
        });
        // SAFETY: VirtualLock only changes how Windows keeps the pages of the region just made.
        let locked = unsafe { VirtualLock(start.as_ptr().cast(), bytes) } != 0;
        Self {
            start,
            bytes,
            locked,
            excluded: exclude_from_reports(start, bytes),
            raised: 0,
        }
    }

    /// The work area of a computation: committed pages, or `None` when Windows refuses them. They are
    /// locked after the working set grew by their size, which a refusal, such as
    /// `ERROR_NO_SYSTEM_RESOURCES`, leaves unlocked; they are left out of error reports in blocks
    /// below 4 GiB, as far as the 512 registrations of a process reach.
    pub(crate) fn work_area(bytes: usize) -> Option<Self> {
        let start = commit(bytes)?;
        let raised = if move_working_set(bytes.cast_signed()) {
            bytes
        } else {
            0
        };
        // SAFETY: as in `new`.
        let locked = raised > 0 && unsafe { VirtualLock(start.as_ptr().cast(), bytes) } != 0;
        Some(Self {
            start,
            bytes,
            locked,
            excluded: exclude_from_reports(start, bytes),
            raised,
        })
    }

    pub(crate) fn is_out_of_dumps(&self) -> bool {
        self.excluded == self.bytes.div_ceil(REPORT_BLOCK)
    }

    /// A process that Windows starts maps none of this process's memory.
    pub(crate) fn is_out_of_children(&self) -> bool {
        true
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        let start = self.start.as_ptr();
        for block in 0..self.excluded {
            // SAFETY: gives back a registration `exclude_from_reports` made for this region.
            unsafe {
                WerUnregisterExcludedMemoryBlock(start.wrapping_add(block * REPORT_BLOCK).cast())
            };
        }
        if self.locked {
            // SAFETY: unlocks the pages the constructor locked.
            unsafe { VirtualUnlock(start.cast(), self.bytes) };
        }
        // SAFETY: the reservation, guard pages included, belongs to this value alone and nothing
        // borrows it any more.
        unsafe { VirtualFree(start.wrapping_sub(page_size()).cast(), 0, MEM_RELEASE) };
        if self.raised > 0 {
            move_working_set(-self.raised.cast_signed());
        }
    }
}

/// A new committed region of `bytes` bytes between two guard pages, which stay reserved and never
/// committed, so that a run past either end faults instead of reaching other memory; `None` when
/// Windows refuses it.
fn commit(bytes: usize) -> Option<NonNull<u8>> {
    let page = page_size();
    let total = bytes
        .checked_next_multiple_of(page)?
        .checked_add(2 * page)?;
    // SAFETY: a new reservation, at an address Windows chooses, takes no memory that anything else
    // owns.
    let reserved = unsafe { VirtualAlloc(ptr::null(), total, MEM_RESERVE, PAGE_NOACCESS) };
    let base = NonNull::new(reserved.cast::<u8>())?;
    let start = base.as_ptr().wrapping_add(page);
    // SAFETY: commits the pages between the guards of the reservation just made.
    let committed = unsafe { VirtualAlloc(start.cast(), bytes, MEM_COMMIT, PAGE_READWRITE) };
    if committed.is_null() {
        // SAFETY: gives back the reservation just made, which nothing refers to.
        unsafe { VirtualFree(base.as_ptr().cast(), 0, MEM_RELEASE) };
        return None;
    }
    NonNull::new(start)
}

impl Region {
    /// Lets the pages be reached as `access` says, and returns whether Windows agreed.
    pub(crate) fn allow(self, access: Access) -> bool {
        let protection = match access {
            Access::Nothing => PAGE_NOACCESS,
            Access::Read => PAGE_READONLY,
            Access::ReadWrite => PAGE_READWRITE,
        };
        let mut previous: PAGE_PROTECTION_FLAGS = 0;
        // SAFETY: changes the protection of pages a `Pages` of this crate owns and writes the old
        // one; the caller makes no reference to them while they refuse it.
        unsafe {
            VirtualProtect(
                self.start.as_ptr().cast(),
                self.bytes,
                protection,
                &mut previous,
            ) != 0
        }
    }
}

/// The size of a memory page.
fn page_size() -> usize {
    // SAFETY: GetSystemInfo fills the struct it is given.
    let info: SYSTEM_INFO = unsafe {
        let mut info = std::mem::zeroed();
        GetSystemInfo(&mut info);
        info
    };
    info.dwPageSize as usize
}

/// Registers the region with Windows Error Reporting in blocks of [`REPORT_BLOCK`] bytes or fewer,
/// until a registration is refused, and returns how many were made.
fn exclude_from_reports(start: NonNull<u8>, bytes: usize) -> usize {
    let mut excluded = 0;
    for offset in (0..bytes).step_by(REPORT_BLOCK) {
        let size = (bytes - offset).min(REPORT_BLOCK) as u32;
        // SAFETY: the block lies inside the region, which stays until `drop` unregisters it.
        let registered = unsafe {
            WerRegisterExcludedMemoryBlock(start.as_ptr().wrapping_add(offset).cast(), size)
        } == S_OK;
        if !registered {
            break;
        }
        excluded += 1;
    }
    excluded
}

/// Moves the minimum and maximum working set by `change` bytes, and returns whether Windows
/// agreed. A refusal leaves them, and `VirtualLock` then locks what still fits.
fn move_working_set(change: isize) -> bool {
    // Reading the limits and setting them again is one step for every page of this crate: two
    // threads in between would lose one change, and every later drop would take back more than
    // was given.
    static MOVING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _moving = MOVING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut minimum, mut maximum, mut flags) = (0, 0, 0);
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing; the call writes
    // the three values it is given.
    let read = unsafe {
        GetProcessWorkingSetSizeEx(GetCurrentProcess(), &mut minimum, &mut maximum, &mut flags)
    } != 0;
    // SAFETY: changes only the working-set limits of this process.
    read && unsafe {
        SetProcessWorkingSetSizeEx(
            GetCurrentProcess(),
            minimum.saturating_add_signed(change),
            maximum.saturating_add_signed(change),
            flags,
        )
    } != 0
}

/// The access list the process gets: one entry, for its owner (OWNER RIGHTS, `OW`), which replaces
/// the owner's implicit rights to read and change the list, and grants only SYNCHRONIZE,
/// PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_TERMINATE (0x0010_1001); `P` keeps out the entries
/// a parent would pass on.
const PROCESS_ACCESS: PCWSTR = w!("D:P(A;;0x101001;;;OW)");
/// The access list of every thread, and the default list of the token, which the threads started
/// later get: one entry for the owner, as above, granting only READ_CONTROL, SYNCHRONIZE and
/// THREAD_QUERY_LIMITED_INFORMATION (0x0012_0800). READ_CONTROL lets a later call read the lists
/// back, which it can no longer change.
const THREAD_ACCESS: PCWSTR = w!("D:P(A;;0x120800;;;OW)");
/// MAXIMUM_ALLOWED of winnt.h: a handle with every right that the object's list grants.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// The low mandatory level (S-1-16-4096), and its last sub-authority, SECURITY_MANDATORY_LOW_RID.
const LOW_INTEGRITY: PCWSTR = w!("S-1-16-4096");
const LOW_INTEGRITY_RID: u32 = 0x1000;
/// SE_GROUP_INTEGRITY of winnt.h: the SID of a label is a mandatory level.
const GROUP_INTEGRITY: u32 = 0x20;

pub(crate) fn enter(options: Options) -> Isolation {
    // SAFETY: changes only what Windows Error Reporting collects when this process fails.
    unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) };
    if options.dynamic_code {
        mitigate(ProcessDynamicCodePolicy, NO_DYNAMIC_CODE);
    }
    if options.microsoft_signed {
        mitigate(ProcessSignaturePolicy, MICROSOFT_SIGNED_ONLY);
    }
    load_libraries_from_known_places();
    mitigate(ProcessExtensionPointDisablePolicy, NO_EXTENSION_POINTS);
    mitigate(ProcessImageLoadPolicy, KNOWN_IMAGES);
    mitigate(ProcessChildProcessPolicy, NO_CHILD_PROCESSES);
    let speculation_limited = mitigate(ProcessSideChannelIsolationPolicy, SIDE_CHANNELS);
    enter_restricted_job();
    let mut token = ptr::null_mut();
    // Once the token is low, Windows may refuse a later call the right to change it: reading it is
    // enough for the read-backs below.
    // SAFETY: opens the token of this process for reading and changing its defaults, or else for
    // reading only; closed below.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
            &mut token,
        ) != 0
            || OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0
    };
    // The access lists are set while the token still has its own integrity level, and the default
    // one before the threads are listed, so that a thread started meanwhile gets it.
    // SAFETY: the pseudo handle of this process needs no closing and has every right to it,
    // WRITE_DAC included.
    let process = restrict_access(unsafe { GetCurrentProcess() }, PROCESS_ACCESS);
    let default_list = opened && restrict_default(token);
    let threads = restrict_threads();
    // Low integrity keeps the process from writing up, but not where a low label allows it, such
    // as AppData\LocalLow: it is applied, and `no_file_changes` stays false. An AppContainer
    // token is lower still and refuses the change.
    let mut contained = false;
    if opened {
        lower_integrity(token);
        contained = without_network(token);
        // SAFETY: closes the token opened above, once.
        unsafe { CloseHandle(token) };
    }
    let mut debugger = 0;
    // SAFETY: the pseudo handle of this process needs no closing; the call writes one BOOL.
    let debugged = unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut debugger) } == 0
        || debugger != 0;
    // Error reports keep the stacks and registers of the threads, so `no_core_dumps` stays false
    // although the heap is left out.
    Isolation {
        no_memory_reading: process && default_list && threads && !debugged,
        no_new_sockets: contained,
        speculation_limited,
        whole_process: true,
        dynamic_code_refused: holds(ProcessDynamicCodePolicy, NO_DYNAMIC_CODE),
        microsoft_signed_only: holds(ProcessSignaturePolicy, MICROSOFT_SIGNED_ONLY),
        ..Isolation::default()
    }
}

/// `ProhibitDynamicCode` of PROCESS_MITIGATION_DYNAMIC_CODE_POLICY.
const NO_DYNAMIC_CODE: u32 = 1;
/// `MicrosoftSignedOnly` of PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY.
const MICROSOFT_SIGNED_ONLY: u32 = 1;

/// Whether the token is an AppContainer's without capabilities, as [`crate::Worker`] starts its
/// worker: Windows then refuses it the network, the loopback address included, and the user's
/// files.
fn without_network(token: HANDLE) -> bool {
    let read_word = |class| {
        let mut value = 0_u32;
        let mut length = 0;
        // SAFETY: the call writes at most one DWORD into `value`, and the length it needed.
        let read = unsafe {
            GetTokenInformation(
                token,
                class,
                (&raw mut value).cast(),
                size_of::<u32>() as u32,
                &mut length,
            )
        } != 0;
        read.then_some(value)
    };
    // TOKEN_GROUPS starts with its count, a DWORD: a buffer of one DWORD holds an empty list
    // whole, and a longer one does not fit.
    read_word(TokenIsAppContainer) == Some(1) && read_word(TokenCapabilities) == Some(0)
}

/// `DisableExtensionPoints` of PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY: no AppInit DLLs,
/// Winsock layered providers, global window hooks or legacy input methods, the ways another
/// program puts its code into this process.
const NO_EXTENSION_POINTS: u32 = 1;
/// PROCESS_MITIGATION_IMAGE_LOAD_POLICY: no image from a remote share (`NoRemoteImages`), none
/// that a low-integrity process could have written (`NoLowMandatoryLabelImages`), and the system's
/// own copy of a DLL first (`PreferSystem32Images`).
const KNOWN_IMAGES: u32 = 0b111;
/// `NoChildProcessCreation` of PROCESS_MITIGATION_CHILD_PROCESS_POLICY (Windows 10 1709): a
/// program started with the secret in its command line or input would carry it out.
const NO_CHILD_PROCESSES: u32 = 1;
/// PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY (Windows 10 1809): branch targets not shared
/// with the other thread of a core (`SmtBranchTargetIsolation`), a security domain of its own,
/// apart from other processes of the user (`IsolateSecurityDomain`), no page combined with an
/// identical one elsewhere (`DisablePageCombine`), and speculative store bypass disabled
/// (`SpeculativeStoreBypassDisable`), against Spectre variants 2 and 4 and page-combining timing.
const SIDE_CHANNELS: u32 = 0b1111;

/// Sets a mitigation policy whose structure is one DWORD of flags, for good, and returns whether
/// every flag reads back. An older Windows that lacks the policy refuses it.
fn mitigate(policy: PROCESS_MITIGATION_POLICY, flags: u32) -> bool {
    // SAFETY: the policy reads one DWORD, which lives for the call.
    unsafe { SetProcessMitigationPolicy(policy, (&raw const flags).cast(), size_of::<u32>()) };
    holds(policy, flags)
}

/// Whether every flag of a mitigation policy whose structure is one DWORD holds, whoever set it.
fn holds(policy: PROCESS_MITIGATION_POLICY, flags: u32) -> bool {
    let mut read = 0_u32;
    // SAFETY: the policy writes one DWORD; the pseudo handle of this process needs no closing.
    let got = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            policy,
            (&raw mut read).cast(),
            size_of::<u32>(),
        )
    } != 0;
    got && read & flags == flags
}

/// Loads later DLLs only from the program's folder and System32, never from the current folder or
/// `PATH`, where another program could have planted one of the same name.
fn load_libraries_from_known_places() {
    // SAFETY: changes only where this process looks for the DLLs it loads afterwards.
    unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
    };
}

/// Puts the process into a job of its own that blocks writing the clipboard, global atoms, other
/// processes' windows and desktop changes, and allows only one process. Reading the clipboard stays,
/// so people can paste a secret in.
fn enter_restricted_job() {
    // SAFETY: makes a new unnamed job; its handle is closed below.
    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        return;
    }
    let interface = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_EXITWINDOWS,
    };
    let limits = JOBOBJECT_BASIC_LIMIT_INFORMATION {
        LimitFlags: JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        ActiveProcessLimit: 1,
        ..JOBOBJECT_BASIC_LIMIT_INFORMATION::default()
    };
    // SAFETY: each call reads the struct it is given, which lives for the call; the job and this
    // process's pseudo handle stay valid for them.
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            (&raw const interface).cast(),
            size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        );
        SetInformationJobObject(
            job,
            JobObjectBasicLimitInformation,
            (&raw const limits).cast(),
            size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
        );
        AssignProcessToJobObject(job, GetCurrentProcess());
        CloseHandle(job);
    }
}

/// Hands the access list of the descriptor `access` to `apply`, and returns its answer; false
/// when the string makes no list.
fn with_access_list(access: PCWSTR, apply: impl FnOnce(*mut ACL) -> bool) -> bool {
    let mut descriptor = ptr::null_mut();
    // SAFETY: the string is NUL-terminated; the call allocates the descriptor, freed below.
    let made = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            access,
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } != 0;
    if !made {
        return false;
    }
    let (mut present, mut defaulted, mut list) = (0, 0, ptr::null_mut());
    // SAFETY: points `list` into the descriptor just made, which lives until it is freed.
    let found =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut list, &mut defaulted) }
            != 0
            && present != 0;
    let holds = found && apply(list);
    // SAFETY: frees the descriptor the conversion allocated, once, after its last use.
    unsafe { LocalFree(descriptor) };
    holds
}

/// Gives `object` the access list of `access`, and returns whether its list reads back as that
/// one entry. Only the reading decides: a list that an earlier call or the token's default gave
/// the object refuses the change, and holds.
fn restrict_access(object: HANDLE, access: PCWSTR) -> bool {
    with_access_list(access, |wanted| {
        // SAFETY: the handle is open, and the list lives for the call.
        unsafe {
            SetSecurityInfo(
                object,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                wanted,
                ptr::null(),
            )
        };
        access_reads_back(object, wanted)
    })
}

/// Whether the access list of `object` holds exactly the one entry of `wanted`.
fn access_reads_back(object: HANDLE, wanted: *const ACL) -> bool {
    let (mut current, mut descriptor) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: the call points `current` into a descriptor it allocates, freed below.
    let read = unsafe {
        GetSecurityInfo(
            object,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut current,
            ptr::null_mut(),
            &mut descriptor,
        )
    } == ERROR_SUCCESS;
    if !read {
        return false;
    }
    // SAFETY: both lists are valid while their descriptors live, which they do here.
    let same = unsafe { same_only_entry(current, wanted) };
    // SAFETY: frees the descriptor GetSecurityInfo allocated, once, after its last use.
    unsafe { LocalFree(descriptor) };
    same
}

/// Makes the access list of [`THREAD_ACCESS`] the default list of `token`, which every object the
/// process makes afterwards without a list of its own gets, and returns whether it reads back as
/// that one entry.
fn restrict_default(token: HANDLE) -> bool {
    with_access_list(THREAD_ACCESS, |wanted| {
        let default = TOKEN_DEFAULT_DACL {
            DefaultDacl: wanted,
        };
        // SAFETY: the structure and its list live for the call, which copies them into the token.
        unsafe {
            SetTokenInformation(
                token,
                TokenDefaultDacl,
                (&raw const default).cast(),
                size_of::<TOKEN_DEFAULT_DACL>() as u32,
            )
        };
        // TOKEN_DEFAULT_DACL and the list after it, of one entry with a SID of one sub-authority:
        // 36 bytes, well within 256, in words aligned for the pointer.
        let mut buffer = [0u64; 32];
        let mut length = 0;
        // SAFETY: the call writes at most the buffer's length into it, and the length it needed.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenDefaultDacl,
                buffer.as_mut_ptr().cast(),
                size_of::<[u64; 32]>() as u32,
                &mut length,
            )
        } != 0;
        // SAFETY: the call filled the buffer with a pointer to a list inside it, or a null one;
        // `wanted` lives for the closure.
        read && unsafe {
            let current = (*buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl;
            same_only_entry(current, wanted)
        }
    })
}

/// Gives every thread of the process [`THREAD_ACCESS`] as its access list, and returns whether
/// each reads back so.
fn restrict_threads() -> bool {
    // SAFETY: takes a snapshot of the threads of the system, closed below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return false;
    }
    // SAFETY: returns the number of this process.
    let process = unsafe { GetCurrentProcessId() };
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    // SAFETY: fills `entry`, whose size it names, from the snapshot.
    let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    // The list holds the calling thread at least.
    let mut all = more;
    while more {
        if entry.th32OwnerProcessID == process {
            all &= restrict_thread(entry.th32ThreadID, process);
        }
        // SAFETY: as above.
        more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    // SAFETY: reads this thread's last error, which Thread32Next set: the end of the list, or a
    // failure that may have left threads out.
    all &= unsafe { GetLastError() } == ERROR_NO_MORE_FILES;
    // SAFETY: closes the snapshot taken above, once.
    unsafe { CloseHandle(snapshot) };
    all
}

/// Gives the thread numbered `id` [`THREAD_ACCESS`] as its access list, and returns whether it
/// reads back so. A thread that has ended since the snapshot is left out, and so is the thread
/// of another process that has taken its number since.
fn restrict_thread(id: u32, process: u32) -> bool {
    // SAFETY: opens the thread with what its list grants: every right while it has the list it
    // started with; READ_CONTROL and THREAD_QUERY_LIMITED_INFORMATION once it has THREAD_ACCESS.
    // Closed below.
    let thread = unsafe { OpenThread(MAXIMUM_ALLOWED, 0, id) };
    if thread.is_null() {
        // SAFETY: reads this thread's last error, which OpenThread set.
        return unsafe { GetLastError() } == ERROR_INVALID_PARAMETER;
    }
    // SAFETY: the handle is open, with THREAD_QUERY_LIMITED_INFORMATION under either list.
    let owner = unsafe { GetProcessIdOfThread(thread) };
    let holds = owner != 0 && (owner != process || restrict_access(thread, THREAD_ACCESS));
    // SAFETY: closes the handle opened above, once.
    unsafe { CloseHandle(thread) };
    holds
}

/// Whether the access lists `current` and `wanted` each hold one entry, and the same one.
///
/// # Safety
///
/// Each list is null or points to a valid access list.
unsafe fn same_only_entry(current: *const ACL, wanted: *const ACL) -> bool {
    // The bytes of the one entry of a list; `None` for a list with none or several.
    let only_entry = |list: *const ACL| {
        // SAFETY: by the contract above.
        if unsafe { list.as_ref() }?.AceCount != 1 {
            return None;
        }
        let mut entry = ptr::null_mut();
        // SAFETY: the list holds entry 0; GetAce points `entry` at it, inside the list.
        if unsafe { GetAce(list, 0, &mut entry) } == 0 {
            return None;
        }
        // SAFETY: an entry starts with its header, whose AceSize counts the whole entry, which
        // lies inside the list.
        Some(unsafe {
            let size = (*entry.cast::<ACE_HEADER>()).AceSize;
            slice::from_raw_parts(entry.cast::<u8>(), size.into())
        })
    };
    only_entry(current).is_some_and(|entry| only_entry(wanted) == Some(entry))
}

/// Lowers `token`, the token of the process, to low integrity, and returns whether it reads back
/// so.
fn lower_integrity(token: HANDLE) -> bool {
    let mut low = ptr::null_mut();
    // SAFETY: the string is NUL-terminated; the call allocates the SID, freed below.
    if unsafe { ConvertStringSidToSidW(LOW_INTEGRITY, &mut low) } != 0 {
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: low,
                Attributes: GROUP_INTEGRITY,
            },
        };
        // SAFETY: the label and its SID live for the call, whose length counts both; lowering
        // the level needs no privilege. Then frees the SID the conversion allocated, once.
        unsafe {
            let length = size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(low);
            SetTokenInformation(
                token,
                TokenIntegrityLevel,
                (&raw const label).cast(),
                length,
            );
            LocalFree(low);
        }
    }
    integrity_of(token).is_some_and(|rid| rid <= LOW_INTEGRITY_RID)
}

/// The mandatory level of `token`: the last sub-authority of its label's SID.
fn integrity_of(token: HANDLE) -> Option<u32> {
    // TOKEN_MANDATORY_LABEL and the SID it points to, which has one sub-authority: well within 64
    // bytes, in words aligned for the pointer.
    let mut buffer = [0u64; 8];
    let mut length = 0;
    // SAFETY: the call writes at most the buffer's length into it, and the length it needed.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            buffer.as_mut_ptr().cast(),
            size_of::<[u64; 8]>() as u32,
            &mut length,
        )
    } != 0;
    if !read {
        return None;
    }
    // SAFETY: the call filled the buffer with a label whose SID lies inside it; the SID's count
    // of sub-authorities names the last one.
    unsafe {
        let sid = (*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        let last = u32::from(*GetSidSubAuthorityCount(sid)).checked_sub(1)?;
        Some(*GetSidSubAuthority(sid, last))
    }
}

/// Writes `text` to standard output: on a console as UTF-16 with `WriteConsoleW`, from a
/// [`Secret`], else as UTF-8 with `WriteFile`; again for what a partial write left.
pub(crate) fn write_secret(text: &str) -> io::Result<()> {
    // SAFETY: returns the handle of standard output, which this process does not own and keeps
    // open; a missing one makes the writes below fail.
    let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let mut mode = 0;
    // SAFETY: writes the console mode into `mode`, and fails when the handle is no console.
    if unsafe { GetConsoleMode(output, &mut mode) } == 0 {
        return write_all(text.as_bytes(), 1, |bytes, length, written| {
            // SAFETY: WriteFile reads `length` bytes of `bytes`, which live for the call.
            unsafe { WriteFile(output, bytes.as_ptr(), length, written, ptr::null_mut()) }
        });
    }
    let mut wide = Secret::zeroed(2 * text.encode_utf16().count());
    let (units, _) = wide.as_mut_bytes().as_chunks_mut::<2>();
    for (bytes, unit) in units.iter_mut().zip(text.encode_utf16()) {
        *bytes = unit.to_ne_bytes();
    }
    write_all(wide.as_bytes(), 2, |bytes, length, written| {
        // SAFETY: the pages of a secret begin on a page, so its bytes are aligned UTF-16 units;
        // WriteConsoleW reads `length` of them, which live for the call.
        unsafe { WriteConsoleW(output, bytes.as_ptr().cast(), length, written, ptr::null()) }
    })
}

/// Hands `bytes`, in units of `unit` bytes, to `write` until it has taken them all; `write` takes
/// the rest, the number of units to write and where it counts those it wrote, and returns
/// nonzero on success.
fn write_all(
    mut bytes: &[u8],
    unit: usize,
    write: impl Fn(&[u8], u32, &mut u32) -> i32,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let length = u32::try_from(bytes.len() / unit).unwrap_or(u32::MAX);
        let mut written = 0;
        if write(bytes, length, &mut written) == 0 {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            // As `Write::write_all` does: a write that takes nothing would be asked again forever.
            return Err(io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[written as usize * unit..];
    }
    Ok(())
}

/// The parent's end of a worker: pipes to its standard input and from its standard output, and
/// the process.
pub(crate) struct WorkerProcess {
    pub(crate) to: Option<std::fs::File>,
    pub(crate) from: std::fs::File,
    process: std::os::windows::io::OwnedHandle,
}

impl WorkerProcess {
    /// Starts this program again in its own AppContainer: no capabilities, no console, an environment
    /// with only the worker variable, and only its two pipes inherited. The program file must be
    /// readable by app containers (Program Files is), or Windows refuses to start it.
    pub(crate) fn start(options: u32, terminal: bool) -> io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        if terminal {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let program = std::env::current_exe()?;
        let path: Vec<u16> = program.as_os_str().encode_wide().chain([0]).collect();
        let container = Container::of(&path)?;
        let pipes = Pipes::new()?;
        let process = container.start(&path, &pipes, options)?;
        Ok(Self {
            to: Some(std::fs::File::from(pipes.parent_in)),
            from: std::fs::File::from(pipes.parent_out),
            process,
        })
    }

    /// Closes the worker's input, which ends it, and waits for it.
    pub(crate) fn finish(&mut self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};
        self.to = None;
        // SAFETY: waits on the process handle this value owns.
        unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), INFINITE) };
    }
}

/// The SID of the program's AppContainer, freed when dropped.
struct Container(windows_sys::Win32::Security::PSID);

impl Container {
    /// The AppContainer of the program at `path` (NUL-terminated UTF-16), made at its first start:
    /// one per program, named after the FNV-1a digest of its path.
    fn of(path: &[u16]) -> io::Result<Self> {
        use windows_sys::Win32::Security::Isolation::{
            CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
        };
        let digest = path.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, &unit| {
            (hash ^ u64::from(unit)).wrapping_mul(0x0100_0000_01b3)
        });
        let name: Vec<u16> = format!("secret-protection-core.{digest:016x}")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut sid = ptr::null_mut();
        // SAFETY: the names are NUL-terminated; the call writes the container's SID into `sid`,
        // which `Container` frees. A profile made by an earlier start answers ERROR_ALREADY_EXISTS.
        let made = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                ptr::null(),
                0,
                &mut sid,
            )
        } >= 0;
        let mut derived = || {
            // SAFETY: as above, for a profile that exists.
            unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) >= 0 }
        };
        if made || derived() {
            Ok(Self(sid))
        } else {
            Err(io::Error::other(
                "Windows made no AppContainer for the worker",
            ))
        }
    }

    /// Starts the program at `path` in this AppContainer, without capabilities, its standard input
    /// and output the child's ends of `pipes`, which are the only handles it inherits, and with the
    /// worker's variable alone in its environment.
    fn start(
        &self,
        path: &[u16],
        pipes: &Pipes,
        options: u32,
    ) -> io::Result<std::os::windows::io::OwnedHandle> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
        use windows_sys::Win32::System::Threading::{
            CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
            InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW, UpdateProcThreadAttribute,
        };
        let handles: [HANDLE; 2] = [
            pipes.child_in.as_raw_handle().cast(),
            pipes.child_out.as_raw_handle().cast(),
        ];
        let capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: self.0,
            Capabilities: ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut size = 0;
        // SAFETY: with no list, the call only answers the size of a list of two attributes.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut size) };
        let mut memory = vec![0_u64; size.div_ceil(8)];
        let list = memory.as_mut_ptr().cast();
        // SAFETY: the list has room for two attributes; each points to a value that lives until
        // the process is made, after which the list is deleted.
        let listed = unsafe {
            InitializeProcThreadAttributeList(list, 2, 0, &mut size) != 0
                && UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    (&raw const capabilities).cast(),
                    size_of::<SECURITY_CAPABILITIES>(),
                    ptr::null_mut(),
                    ptr::null(),
                ) != 0
                && UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    size_of::<[HANDLE; 2]>(),
                    ptr::null_mut(),
                    ptr::null(),
                ) != 0
        };
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.lpAttributeList = list;
        let mut environment: Vec<u16> = format!("{}={options}", crate::worker::WORKER)
            .encode_utf16()
            .chain([0, 0])
            .collect();
        let mut command: Vec<u16> = [u16::from(b'"')]
            .into_iter()
            .chain(path[..path.len() - 1].iter().copied())
            .chain([u16::from(b'"'), 0])
            .collect();
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: every pointer is valid for the call: the NUL-terminated path, the command line,
        // which the call may change, the environment block ending in two NULs, and the startup
        // information with its attribute list.
        let started = listed
            && unsafe {
                CreateProcessW(
                    path.as_ptr(),
                    command.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    1,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    environment.as_mut_ptr().cast(),
                    ptr::null(),
                    &startup.StartupInfo,
                    &mut information,
                )
            } != 0;
        let error = io::Error::last_os_error();
        // SAFETY: deletes the list initialized above; a list the call left as zeros is ignored.
        unsafe { DeleteProcThreadAttributeList(list) };
        if !started {
            return Err(error);
        }
        // SAFETY: the process and thread handles were just made and nothing else owns them.
        unsafe {
            CloseHandle(information.hThread);
            Ok(OwnedHandle::from_raw_handle(information.hProcess.cast()))
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // SAFETY: frees the SID the profile call allocated, once.
        unsafe { windows_sys::Win32::Security::FreeSid(self.0) };
    }
}

/// The two pipes of a worker: the child's ends inheritable, the parent's not.
struct Pipes {
    child_in: std::os::windows::io::OwnedHandle,
    parent_in: std::os::windows::io::OwnedHandle,
    parent_out: std::os::windows::io::OwnedHandle,
    child_out: std::os::windows::io::OwnedHandle,
}

impl Pipes {
    fn new() -> io::Result<Self> {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::Pipes::CreatePipe;
        let inherited = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1,
        };
        let pipe = || -> io::Result<(OwnedHandle, OwnedHandle)> {
            let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
            // SAFETY: the call writes two new handles, which nothing else owns.
            if unsafe { CreatePipe(&mut read, &mut write, &inherited, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: as above; the owners close them when dropped.
            Ok(unsafe {
                (
                    OwnedHandle::from_raw_handle(read.cast()),
                    OwnedHandle::from_raw_handle(write.cast()),
                )
            })
        };
        let (child_in, parent_in) = pipe()?;
        let (parent_out, child_out) = pipe()?;
        for parent in [&parent_in, &parent_out] {
            use std::os::windows::io::AsRawHandle;
            // SAFETY: changes only whether a child inherits the handle.
            if unsafe {
                SetHandleInformation(parent.as_raw_handle().cast(), HANDLE_FLAG_INHERIT, 0)
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            child_in,
            parent_in,
            parent_out,
            child_out,
        })
    }
}

/// A worker inherits no handle but its pipes: nothing to close.
pub(crate) fn close_inherited() {}

/// Windows has no plain way for a process to list its own handles.
pub(crate) fn open_channels() -> Option<Vec<crate::Channel>> {
    None
}

/// `CreateThread` takes no stack memory from its caller, so a protected stack is not offered.
pub(crate) fn run_on_stack<R>(_bytes: usize, _work: impl FnOnce() -> R) -> io::Result<(R, bool)> {
    Err(io::ErrorKind::Unsupported.into())
}

/// The worker's standard input and output, unbuffered; they stay open when dropped.
pub(crate) fn worker_streams() -> (
    std::mem::ManuallyDrop<std::fs::File>,
    std::mem::ManuallyDrop<std::fs::File>,
) {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::System::Console::STD_INPUT_HANDLE;
    // SAFETY: the standard handles are the pipes the parent made, open for the whole process;
    // `ManuallyDrop` never closes them.
    unsafe {
        (
            std::mem::ManuallyDrop::new(std::fs::File::from_raw_handle(
                GetStdHandle(STD_INPUT_HANDLE).cast(),
            )),
            std::mem::ManuallyDrop::new(std::fs::File::from_raw_handle(
                GetStdHandle(STD_OUTPUT_HANDLE).cast(),
            )),
        )
    }
}

/// What confirms each protection on Windows, where everything holds for the whole process.
pub(crate) fn measure(protection: crate::Protection) -> (bool, &'static str) {
    use crate::Protection::*;
    let proof = match protection {
        NoCoreDumps => "not offered: error reports keep the threads' stacks",
        NoMemoryReading => "the access lists read back, and no debugger is present",
        NoNewSockets => "an AppContainer token without capabilities",
        NoFileChanges => "not offered: low integrity still writes where a low label allows",
        SpeculationLimited => "the side-channel policy reads back",
        WholeProcess => "everything here holds for the process",
        DynamicCodeRefused => "the dynamic-code policy reads back",
        MicrosoftSignedOnly => "the signature policy reads back",
        EmptyNetwork | FileLocksRefused | SendmsgRefused | ForeignSignalsRefused | MemoryLocked => {
            "Linux and Android only"
        }
    };
    (true, proof)
}
