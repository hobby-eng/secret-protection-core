// long: pages, access lists, mitigations and integrity of one Windows process, read whole.
//! Windows allocations use `VirtualAlloc`. Each region records whether `VirtualLock` and
//! registration with Windows Error Reporting succeeded. This module also implements process
//! isolation and console output.
#![allow(
    unsafe_code,
    reason = "the memory, error-reporting, security, thread and console calls of Windows are \
              foreign functions"
)]

mod console;
mod threads;
mod worker;

use std::collections::BTreeMap;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::Once;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_SUCCESS, GetLastError, HANDLE,
    LocalFree, S_OK, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid, GetSecurityDescriptorDacl,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
    PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES,
    SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenCapabilities, TokenDefaultDacl, TokenIntegrityLevel, TokenIsAppContainer,
};
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_OUTPUT_HANDLE, WriteConsoleW,
};
use windows_sys::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
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
    JobObjectBasicLimitInformation, JobObjectBasicUIRestrictions, QueryInformationJobObject,
    SetInformationJobObject,
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
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, GetProcessIdOfThread,
    GetProcessMitigationPolicy, OpenProcessToken, OpenThread, PROCESS_MITIGATION_POLICY,
    ProcessChildProcessPolicy, ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy,
    ProcessImageLoadPolicy, ProcessSideChannelIsolationPolicy, ProcessSignaturePolicy,
    SetProcessMitigationPolicy, WaitForSingleObject,
};
use windows_sys::core::{PCWSTR, w};

pub(crate) use console::HiddenTerminal;
pub(crate) use worker::{WorkerProcess, leave_terminal, starts_clean, worker_streams};

use super::{Access, Pages, Region};
use crate::protect::{Findings, Isolation, Options, Secret};
use crate::{Outcome, Protection};

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

    /// Commits pages and attempts to grow the working set. `VirtualLock` determines whether
    /// the pages are locked, even if the working set could not grow. Dump exclusion is checked
    /// separately through Windows Error Reporting registrations.
    pub(crate) fn work_area(bytes: usize) -> Option<Self> {
        let start = commit(bytes)?;
        let raised = if isize::try_from(bytes).is_ok_and(move_working_set) {
            bytes
        } else {
            0
        };
        // The working set as it is may hold the pages even when it could not grow.
        // SAFETY: as in `new`.
        let locked = unsafe { VirtualLock(start.as_ptr().cast(), bytes) } != 0;
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

    /// Records that the pages lost their lock, as Windows takes it from a page it makes
    /// inaccessible, so that the drop does not unlock them again.
    pub(crate) fn lock_lost(&mut self) {
        self.locked = false;
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
        if let Ok(raised) = isize::try_from(self.raised)
            && raised > 0
        {
            move_working_set(-raised);
        }
    }
}

/// A new committed region of `bytes` bytes between two guard pages, which stay reserved and never
/// committed, so that a run past either end faults instead of reaching other memory; `None` when
/// Windows refuses it.
fn commit(bytes: usize) -> Option<NonNull<u8>> {
    let page = page_size();
    // No more than `isize::MAX` bytes in all, so that a slice of them is sound.
    let total = super::reservation(bytes, page)?;
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
/// the owner's implicit rights to read and change the list, and grants only SYNCHRONIZE and
/// PROCESS_TERMINATE (0x0010_0001); `P` keeps out the entries a parent would pass on. Not
/// PROCESS_QUERY_LIMITED_INFORMATION, with which another process of the user would open the
/// process's token and change the default list of the threads it starts later.
const PROCESS_ACCESS: PCWSTR = w!("D:P(A;;0x100001;;;OW)");
/// The access list of every thread, and the default list of the token, which the threads started
/// later get: one entry for the owner, as above, granting only READ_CONTROL, SYNCHRONIZE and
/// THREAD_QUERY_LIMITED_INFORMATION (0x0012_0800). READ_CONTROL lets a later call read the lists
/// back, which it can no longer change.
const THREAD_ACCESS: PCWSTR = w!("D:P(A;;0x120800;;;OW)");

/// The default list a worker's token has from its start until its census (`worker::Container`):
/// [`THREAD_ACCESS`], and the same rights for the worker's `package` SID, without which the
/// worker, an AppContainer process, could not open the threads Windows starts in it meanwhile and
/// read their lists back. No process gets more than THREAD_ACCESS gives the user.
fn start_up_access(package: &str) -> Vec<u16> {
    format!("D:P(A;;0x120800;;;OW)(A;;0x120800;;;{package})")
        .encode_utf16()
        .chain([0])
        .collect()
}

/// MAXIMUM_ALLOWED of winnt.h: a handle with every right that the object's list grants.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// The low mandatory level (S-1-16-4096), and its last sub-authority, SECURITY_MANDATORY_LOW_RID.
const LOW_INTEGRITY: PCWSTR = w!("S-1-16-4096");
const LOW_INTEGRITY_RID: u32 = 0x1000;
/// SE_GROUP_INTEGRITY of winnt.h: the SID of a label is a mandatory level.
const GROUP_INTEGRITY: u32 = 0x20;

pub(crate) fn enter(options: Options) -> Isolation {
    let Ok(report) = enter_with_census(options, |_| {
        Ok::<_, std::convert::Infallible>(threads::current_ids().ok())
    });
    report
}

/// Each census is requested at the point it is needed. Only the worker protocol can
/// substitute the launcher's view for the one available to a standalone process.
fn enter_with_census<E>(
    options: Options,
    mut census: impl FnMut(threads::Phase) -> Result<Option<Vec<u32>>, E>,
) -> Result<Isolation, E> {
    // SAFETY: changes only what Windows Error Reporting collects when this process fails.
    unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) };
    if options.dynamic_code {
        mitigate(
            ProcessDynamicCodePolicy,
            NO_DYNAMIC_CODE,
            DYNAMIC_CODE_WAYS_OUT,
        );
    }
    if options.microsoft_signed {
        mitigate(ProcessSignaturePolicy, MICROSOFT_SIGNED_ONLY, 0);
    }
    // Each of the three is tried whatever became of the others.
    let known_places = load_libraries_from_known_places();
    let no_extensions = mitigate(ProcessExtensionPointDisablePolicy, NO_EXTENSION_POINTS, 0);
    let known_images = mitigate(ProcessImageLoadPolicy, KNOWN_IMAGES, 0);
    let no_programs = mitigate(
        ProcessChildProcessPolicy,
        NO_CHILD_PROCESSES,
        SECURE_PROCESSES_ALLOWED,
    );
    let speculation_limited = mitigate(ProcessSideChannelIsolationPolicy, SIDE_CHANNELS, 0);
    let desktop_restricted = enter_restricted_job();
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
    let default_list = opened && restrict_default(token, THREAD_ACCESS);
    // SAFETY: only a successful token open transfers ownership. Keep the token owned
    // across protocol errors so an interrupted startup cannot leak it.
    let _token_owner = opened.then(|| unsafe { OwnedHandle::from_raw_handle(token.cast()) });
    // A worker's threads that Windows started before this point keep their start-up list.
    let start_up = if opened { start_up_list(token) } else { None };
    let mut pinned = BTreeMap::new();
    let (threads, _) = inspect_threads(
        census(threads::Phase::Access)?,
        true,
        start_up.as_ref().and_then(Descriptor::access_list),
        &mut pinned,
    );
    // Low integrity keeps the process from writing up, but not where a low label allows it, such
    // as AppData\LocalLow: it is applied, and file changes stay unreported. An AppContainer
    // token is lower still and refuses the change.
    let (mut low, mut contained) = (Outcome::Unknown, false);
    if opened {
        low = lower_integrity(token);
        contained = without_network(token);
    }
    let mut debugger = 0;
    // SAFETY: the pseudo handle of this process needs no closing; the call writes one BOOL.
    let debugged = unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut debugger) } == 0
        || debugger != 0;
    let mut found = Findings::new();
    found.set(
        Protection::NoMemoryReading,
        if process && default_list && !debugged {
            threads
        } else {
            Outcome::Refused
        },
        true,
    );
    found.check(Protection::NoNewSockets, contained, true);
    found.check(Protection::SpeculationLimited, speculation_limited, true);
    found.check(Protection::WholeProcess, true, true);
    found.check(Protection::NoNewPrograms, no_programs, true);
    found.check(
        Protection::NoPlantedLibraries,
        known_places && no_extensions && known_images,
        true,
    );
    found.check(Protection::DesktopRestricted, desktop_restricted, true);
    let effective_threads = census(threads::Phase::Integrity)?;
    let integrity = match low {
        Outcome::Confirmed => inspect_threads(effective_threads, false, None, &mut pinned).1,
        outcome => outcome,
    };
    found.set(Protection::LowIntegrity, integrity, true);
    found.option(
        Protection::DynamicCodeRefused,
        options.dynamic_code,
        holds(
            ProcessDynamicCodePolicy,
            NO_DYNAMIC_CODE,
            DYNAMIC_CODE_WAYS_OUT,
        ),
        true,
    );
    found.option(
        Protection::MicrosoftSignedOnly,
        options.microsoft_signed,
        holds(ProcessSignaturePolicy, MICROSOFT_SIGNED_ONLY, 0),
        true,
    );
    Ok(found.finish())
}

/// `ProhibitDynamicCode` of PROCESS_MITIGATION_DYNAMIC_CODE_POLICY.
const NO_DYNAMIC_CODE: u32 = 1;
/// `AllowThreadOptOut` and `AllowRemoteDowngrade` of that policy: with either, a thread or another
/// process can lift the prohibition, so it does not count as holding.
const DYNAMIC_CODE_WAYS_OUT: u32 = 0b110;
/// `MicrosoftSignedOnly` of PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY.
const MICROSOFT_SIGNED_ONLY: u32 = 1;

/// Checks for an AppContainer token with an empty capability list. The check neither
/// attempts a connection nor inspects loopback exemptions or filesystem ACLs.
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
    // TOKEN_GROUPS starts with its count, a DWORD, in words aligned for the pointers that
    // follow it. A list too long for the buffer is not read, and is not empty either.
    let mut groups = [0_u64; 16];
    let mut length = 0;
    // SAFETY: the call writes at most the buffer's length into it, and the length it needed.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenCapabilities,
            groups.as_mut_ptr().cast(),
            size_of::<[u64; 16]>() as u32,
            &mut length,
        )
    } != 0;
    let none = read && groups.first().is_some_and(|word| word & 0xFFFF_FFFF == 0);
    read_word(TokenIsAppContainer) == Some(1) && none
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
/// `AllowSecureProcessCreation` of that policy: with it some processes still start, so the
/// policy does not count as holding.
const SECURE_PROCESSES_ALLOWED: u32 = 0b100;
/// PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY (Windows 10 1809): branch targets not shared
/// with the other thread of a core (`SmtBranchTargetIsolation`), a security domain of its own,
/// apart from other processes of the user (`IsolateSecurityDomain`), no page combined with an
/// identical one elsewhere (`DisablePageCombine`), and speculative store bypass disabled
/// (`SpeculativeStoreBypassDisable`), against Spectre variants 2 and 4 and page-combining timing.
const SIDE_CHANNELS: u32 = 0b1111;

/// Sets a mitigation policy whose structure is one DWORD of flags, for good, and returns whether
/// it reads back with every flag and none of `ways_out`. An older Windows that lacks the policy
/// refuses it.
fn mitigate(policy: PROCESS_MITIGATION_POLICY, flags: u32, ways_out: u32) -> bool {
    // SAFETY: the policy reads one DWORD, which lives for the call.
    unsafe { SetProcessMitigationPolicy(policy, (&raw const flags).cast(), size_of::<u32>()) };
    holds(policy, flags, ways_out)
}

/// Whether a mitigation policy whose structure is one DWORD has every flag of `flags` and none
/// of `ways_out`, whoever set it.
fn holds(policy: PROCESS_MITIGATION_POLICY, flags: u32, ways_out: u32) -> bool {
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
    got && read & flags == flags && read & ways_out == 0
}

/// Sets the default DLL search to the application directory and System32. Explicit paths
/// and caller-supplied search flags can select other locations. Windows reports whether
/// it accepted the change.
fn load_libraries_from_known_places() -> bool {
    // SAFETY: changes only where this process looks for the DLLs it loads afterwards.
    unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
            != 0
    }
}

/// What the job keeps the process from: writing the clipboard, global atoms, other processes'
/// windows, and changes of the desktop, its settings and the session.
const DESKTOP_LIMITS: u32 = JOB_OBJECT_UILIMIT_WRITECLIPBOARD
    | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_EXITWINDOWS;

/// Whether the job the process is in has every limit of [`DESKTOP_LIMITS`] and allows one
/// process only, whoever put it there.
fn job_limits_hold() -> bool {
    let mut desktop = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: 0,
    };
    let mut basic = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
    // SAFETY: a null job stands for the one this process is in; each call writes the struct it
    // is given, whose size it is told.
    let got = unsafe {
        QueryInformationJobObject(
            ptr::null_mut(),
            JobObjectBasicUIRestrictions,
            (&raw mut desktop).cast(),
            size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            ptr::null_mut(),
        ) != 0
            && QueryInformationJobObject(
                ptr::null_mut(),
                JobObjectBasicLimitInformation,
                (&raw mut basic).cast(),
                size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
                ptr::null_mut(),
            ) != 0
    };
    got && desktop.UIRestrictionsClass & DESKTOP_LIMITS == DESKTOP_LIMITS
        && basic.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0
        && basic.ActiveProcessLimit == 1
}

/// Puts the process into a job of its own with [`DESKTOP_LIMITS`] that allows only one process,
/// unless its job has both already, and returns whether they read back. Reading the clipboard
/// stays, so people can paste a secret in.
fn enter_restricted_job() -> bool {
    if job_limits_hold() {
        return true;
    }
    // SAFETY: makes a new unnamed job; its handle is closed below.
    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        return false;
    }
    let interface = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: DESKTOP_LIMITS,
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
    job_limits_hold()
}

/// Hands the access list of the descriptor `access` to `apply`, and returns its answer; false
/// when the string makes no list.
fn with_access_list(access: PCWSTR, apply: impl FnOnce(*mut ACL) -> bool) -> bool {
    Descriptor::of(access).is_ok_and(|descriptor| descriptor.access_list().is_some_and(apply))
}

/// A security descriptor made from SDDL text, freed when dropped: for an access list to set and
/// read back, and for the attributes a new object is created with.
struct Descriptor(*mut core::ffi::c_void);

impl Descriptor {
    fn of(sddl: PCWSTR) -> io::Result<Self> {
        let mut descriptor = ptr::null_mut();
        // SAFETY: the string is NUL-terminated; the call allocates the descriptor, freed on drop.
        let made = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } != 0;
        if made {
            Ok(Self(descriptor))
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Attributes naming this descriptor, inherited by no child; they borrow it.
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    /// Its access list, which lives as long as the descriptor.
    fn access_list(&self) -> Option<*mut ACL> {
        let (mut present, mut defaulted, mut list) = (0, 0, ptr::null_mut());
        // SAFETY: points `list` into this descriptor, which outlives every use of the list here.
        let found =
            unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut list, &mut defaulted) }
                != 0
                && present != 0;
        found.then_some(list)
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: frees the descriptor the conversion allocated, once.
        unsafe { LocalFree(self.0) };
    }
}

/// Gives `object` the access list of `access`, and returns whether its list reads back as that
/// one entry. Only the reading decides: a list that an earlier call or the token's default gave
/// the object refuses the change, and holds.
fn restrict_access(object: HANDLE, access: PCWSTR) -> bool {
    with_access_list(access, |wanted| restrict_to(object, wanted))
}

/// [`restrict_access`] with a list made already, as for every thread of a walk.
fn restrict_to(object: HANDLE, wanted: *mut ACL) -> bool {
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
}

/// Whether the access list of `object` holds exactly the entries of `wanted`.
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
    let same = unsafe { same_entries(current, wanted) };
    // SAFETY: frees the descriptor GetSecurityInfo allocated, once, after its last use.
    unsafe { LocalFree(descriptor) };
    same
}

/// Makes the access list of `access` the default list of `token`, which every object the process
/// makes afterwards without a list of its own gets, and returns whether it reads back so.
fn restrict_default(token: HANDLE, access: PCWSTR) -> bool {
    with_access_list(access, |wanted| {
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
        // TOKEN_DEFAULT_DACL and the list after it, of two entries at most, one with a package SID
        // of eight sub-authorities: under 100 bytes, well within 256, in words aligned for the
        // pointer.
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
            same_entries(current, wanted)
        }
    })
}

/// The start-up list ([`start_up_access`]) of a process in an AppContainer, made with the package
/// SID of its `token`; `None` outside one.
fn start_up_list(token: HANDLE) -> Option<Descriptor> {
    use windows_sys::Win32::Security::{TOKEN_APPCONTAINER_INFORMATION, TokenAppContainerSid};
    // TOKEN_APPCONTAINER_INFORMATION and the SID after it, of eight sub-authorities at most: well
    // within 128 bytes, in words aligned for the pointer.
    let mut buffer = [0u64; 16];
    let mut length = 0;
    // SAFETY: the call writes at most the buffer's length into it, and the length it needed.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenAppContainerSid,
            buffer.as_mut_ptr().cast(),
            size_of::<[u64; 16]>() as u32,
            &mut length,
        )
    } != 0;
    if !read {
        return None;
    }
    // SAFETY: the call filled the buffer with a pointer to a SID inside it, or a null one.
    let package =
        unsafe { (*buffer.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer };
    if package.is_null() {
        return None;
    }
    let text = worker::sid_text(package).ok()?;
    Descriptor::of(start_up_access(&text).as_ptr()).ok()
}

/// First pass hardens thread ACLs and pins handles; in a worker it also accepts a thread that keeps
/// the `start_up` list. The second pass checks current effective tokens after the primary token
/// has been lowered.
fn inspect_threads(
    ids: Option<Vec<u32>>,
    set_acl: bool,
    start_up: Option<*mut ACL>,
    pinned: &mut BTreeMap<u32, OwnedHandle>,
) -> (Outcome, Outcome) {
    // SAFETY: these IDs identify the live thread performing this check and its process.
    let (process, caller) = unsafe {
        (
            GetCurrentProcessId(),
            windows_sys::Win32::System::Threading::GetCurrentThreadId(),
        )
    };
    let Some(ids) = ids.filter(|ids| ids.binary_search(&caller).is_ok()) else {
        return (Outcome::Unknown, Outcome::Unknown);
    };
    let mut all = true;
    let mut integrity = Outcome::Confirmed;
    // The threads' list, made once for the whole walk.
    let thread_list = Descriptor::of(THREAD_ACCESS).ok();
    let wanted = thread_list.as_ref().and_then(Descriptor::access_list);
    for id in ids {
        let (restricted, level) =
            inspect_thread(id, process, caller, set_acl, wanted, start_up, pinned);
        all &= restricted;
        if let Some(level) = level
            && (level == Outcome::Refused || integrity == Outcome::Confirmed)
        {
            integrity = level;
        }
    }
    if !set_acl && integrity == Outcome::Confirmed {
        // A pinned thread missing from the second walk must have exited. A failed wait
        // cannot establish that the snapshot covered every previously known live thread.
        let exited = pinned.values().all(|thread| {
            // SAFETY: the retained handle is live, and a zero timeout never blocks.
            unsafe { WaitForSingleObject(thread.as_raw_handle().cast(), 0) == WAIT_OBJECT_0 }
        });
        if !exited {
            integrity = Outcome::Unknown;
        }
    }
    (
        if all {
            Outcome::Confirmed
        } else {
            Outcome::Refused
        },
        integrity,
    )
}

/// Gives the thread numbered `id` [`THREAD_ACCESS`] as its access list, and returns whether it
/// reads back so, or as the `start_up` list. A thread that has ended since the snapshot is left
/// out, and so is the thread of another process that has taken its number since.
fn inspect_thread(
    id: u32,
    process: u32,
    caller: u32,
    set_acl: bool,
    wanted: Option<*mut ACL>,
    start_up: Option<*mut ACL>,
    pinned: &mut BTreeMap<u32, OwnedHandle>,
) -> (bool, Option<Outcome>) {
    if !set_acl && let Some(level) = threads::pinned_integrity(id, pinned) {
        return (true, Some(level));
    }
    // The calling thread goes through its pseudo handle, which has every right whatever its list:
    // an AppContainer worker's first thread starts with THREAD_ACCESS, which grants the worker's
    // package SID nothing, so OpenThread would refuse it.
    if id == caller {
        // SAFETY: the pseudo handle of the calling thread needs no closing.
        let current = unsafe { GetCurrentThread() };
        return (
            wanted.is_some_and(|list| restrict_to(current, list)),
            Some(Outcome::Unknown),
        );
    }
    // SAFETY: opens the thread with what its list grants: every right while it has the list it
    // started with; READ_CONTROL and THREAD_QUERY_LIMITED_INFORMATION once it has THREAD_ACCESS,
    // or in a worker the start-up list. Closed below.
    let thread = unsafe { OpenThread(MAXIMUM_ALLOWED, 0, id) };
    if thread.is_null() {
        // SAFETY: reads this thread's last error, which OpenThread set.
        return if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            (true, None)
        } else {
            (false, Some(Outcome::Unknown))
        };
    }
    // SAFETY: OpenThread transferred one owned handle. Retain its original query rights
    // across ACL hardening and the subsequent lowering of the primary token.
    let opened = unsafe { OwnedHandle::from_raw_handle(thread.cast()) };
    // SAFETY: the handle is open, with THREAD_QUERY_LIMITED_INFORMATION under either list.
    let owner = unsafe { GetProcessIdOfThread(thread) };
    let integrity = if owner == process {
        // A live thread pinned earlier was answered above, by its own handle; here the thread
        // was not pinned, or the one pinned ended and another may have its number.
        Some(if set_acl {
            Outcome::Unknown
        } else {
            thread_integrity(thread)
        })
    } else if owner == 0 {
        Some(Outcome::Unknown)
    } else {
        None
    };
    // A thread Windows started in a worker before its census keeps the start-up list, which the
    // worker can read but not change.
    let holds = owner != 0
        && (owner != process
            || !set_acl
            || wanted.is_some_and(|list| restrict_to(thread, list))
            || start_up.is_some_and(|list| access_reads_back(thread, list)));
    if set_acl && owner == process {
        pinned.insert(id, opened);
    }
    (holds, integrity)
}

/// A thread without an impersonation token follows the primary token checked by enter.
fn thread_integrity(thread: HANDLE) -> Outcome {
    use windows_sys::Win32::Foundation::ERROR_NO_TOKEN;
    use windows_sys::Win32::System::Threading::OpenThreadToken;
    let mut token = ptr::null_mut();
    // SAFETY: thread is pinned by its open handle. OpenAsSelf requests access under the
    // caller's process identity. On failure no token handle was acquired.
    if unsafe { OpenThreadToken(thread, TOKEN_QUERY, 1, &mut token) } == 0 {
        // SAFETY: read the immediately preceding error on this thread.
        return if unsafe { GetLastError() } == ERROR_NO_TOKEN {
            Outcome::Confirmed
        } else {
            Outcome::Unknown
        };
    }
    let level = integrity_of(token);
    // SAFETY: this function owns the token handle returned above.
    unsafe { CloseHandle(token) };
    match level {
        Some(rid) if rid <= LOW_INTEGRITY_RID => Outcome::Confirmed,
        Some(_) => Outcome::Refused,
        None => Outcome::Unknown,
    }
}

/// Whether the access lists `current` and `wanted` hold the same entries, at least one, in the
/// same order.
///
/// # Safety
///
/// Each list is null or points to a valid access list.
unsafe fn same_entries(current: *const ACL, wanted: *const ACL) -> bool {
    // SAFETY: by the contract above.
    let (Some(have), Some(want)) = (unsafe { current.as_ref() }, unsafe { wanted.as_ref() }) else {
        return false;
    };
    // The bytes of entry `at` of a list that holds it.
    let entry = |list: *const ACL, at: u32| {
        let mut entry = ptr::null_mut();
        // SAFETY: the list holds entry `at`; GetAce points `entry` at it, inside the list.
        if unsafe { GetAce(list, at, &mut entry) } == 0 {
            return None;
        }
        // SAFETY: an entry starts with its header, whose AceSize counts the whole entry, which
        // lies inside the list.
        Some(unsafe {
            let size = (*entry.cast::<ACE_HEADER>()).AceSize;
            slice::from_raw_parts(entry.cast::<u8>(), size.into())
        })
    };
    have.AceCount == want.AceCount
        && want.AceCount > 0
        && (0..u32::from(want.AceCount)).all(|at| {
            let wanted_entry = entry(wanted, at);
            wanted_entry.is_some() && entry(current, at) == wanted_entry
        })
}

/// Lowers `token`, the token of the process, to low integrity, and returns whether it reads back
/// so.
fn lower_integrity(token: HANDLE) -> Outcome {
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
    match integrity_of(token) {
        Some(rid) if rid <= LOW_INTEGRITY_RID => Outcome::Confirmed,
        Some(_) => Outcome::Refused,
        None => Outcome::Unknown,
    }
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
    // SAFETY: the call filled the buffer with a label whose SID lies inside it, checked to be a
    // well-formed SID; its count of sub-authorities names the last one.
    unsafe {
        let sid = (*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        if sid.is_null() || IsValidSid(sid) == 0 {
            return None;
        }
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
    // A console takes UTF-16. GetConsoleMode tells one, but needs the read right: a console open
    // only for writing answers ACCESS_DENIED, where NUL, a file or a pipe answer otherwise.
    let mut mode = 0;
    // SAFETY: writes the console mode into `mode`, and fails when the handle is no console.
    let console = unsafe { GetConsoleMode(output, &mut mode) } != 0
        // SAFETY: reads this thread's last error, which GetConsoleMode set.
        || (unsafe { GetLastError() } == ERROR_ACCESS_DENIED && console::character_device(output));
    if !console {
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

/// Windows has no plain way for a process to list its own handles.
pub(crate) fn open_channels() -> io::Result<crate::OpenChannels> {
    Err(io::ErrorKind::Unsupported.into())
}

/// `CreateThread` takes no stack memory from its caller, so a protected stack is not offered.
pub(crate) fn run_on_stack<R>(
    _bytes: usize,
    _required: crate::StackProperties,
    _work: impl FnOnce() -> R,
) -> Result<(R, crate::StackProperties), crate::StackError> {
    Err(crate::StackError::Unsupported)
}

/// What a call observed for `protection` when it reports `outcome`, in words. Error reports
/// without the heap go in without a line of their own here.
pub(crate) fn evidence(protection: Protection, outcome: Outcome) -> Option<&'static str> {
    use {Outcome as O, Protection as P};
    Some(match (protection, outcome) {
        (P::NoCoreDumps, O::Unsupported) => "error reports keep the threads' stacks and registers",
        (P::NoFileChanges, O::Unsupported) => {
            "low integrity still writes where a low label allows it"
        }
        (P::NoMemoryReading, O::Confirmed) => {
            "the access lists read back, and no debugger is present"
        }
        (P::NoMemoryReading, O::Unknown) => "the live thread inventory was unavailable",
        (P::NoMemoryReading, O::Refused) => {
            "access checks failed or the debugger check did not confirm an untraced process"
        }
        (P::NoNewSockets, O::Confirmed) => {
            "the token is an AppContainer's without capabilities (its policy, not a connection tried)"
        }
        (P::NoNewSockets, O::Refused) => {
            "the token check did not confirm an AppContainer with an empty capability list"
        }
        (P::SpeculationLimited, O::Confirmed) => "the side-channel policy reads back",
        (P::SpeculationLimited, O::Refused) => "the side-channel policy did not read back",
        (P::WholeProcess, O::Confirmed) => "this platform applies isolation at process scope",
        (P::NoNewPrograms, O::Confirmed) => {
            "the child-process policy reads back, with no exception for secure processes"
        }
        (P::NoNewPrograms, O::Refused) => {
            "the child-process policy did not read back, or allows secure processes"
        }
        (P::NoPlantedLibraries, O::Confirmed) => {
            "the extension-point and image-load policies read back, and the search for a name was limited"
        }
        (P::NoPlantedLibraries, O::Refused) => {
            "a library policy did not read back, or the limit of the search was refused"
        }
        (P::DesktopRestricted, O::Confirmed) => {
            "the job of the process reads back with the limits and one process"
        }
        (P::DesktopRestricted, O::Refused) => {
            "the process is in no job with the limits and one process"
        }
        (P::LowIntegrity, O::Confirmed) => {
            "the primary token and the effective tokens of the enumerated threads are low or below"
        }
        (P::LowIntegrity, O::Refused) => {
            "the primary token or an observed thread token is above low"
        }
        (P::LowIntegrity, O::Unknown) => {
            "the primary level or at least one live thread’s effective level could not be determined"
        }
        (P::DynamicCodeRefused, O::Confirmed) => {
            "the dynamic-code policy reads back, with no way out for a thread or another process"
        }
        (P::DynamicCodeRefused, O::Refused) => {
            "the dynamic-code policy did not read back, or leaves a way out"
        }
        (P::MicrosoftSignedOnly, O::Confirmed) => "the signature policy reads back",
        (P::MicrosoftSignedOnly, O::Refused) => "the signature policy did not read back",
        _ => return None,
    })
}
