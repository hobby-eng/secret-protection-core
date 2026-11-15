//! Read one process's thread records from the kernel's process inventory.
//! Opening a diagnostic handle to a thread is a separate access check and cannot establish
//! whether that thread exists.

use std::ffi::c_void;
use std::io;
use std::mem::{offset_of, size_of};
use std::slice;

use windows_sys::Win32::Foundation::{STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};
use windows_sys::Win32::System::WindowsProgramming::{
    CLIENT_ID, SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION,
};
use windows_sys::core::w;

// SystemProcessInformation in winternl.h. Only process and thread IDs are read.
const PROCESS_INFORMATION: i32 = 5;
// The inventory includes all system records; refuse an oversized reply before allocating it.
const MAX_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_THREADS: usize = 65_536;
#[derive(Clone, Copy)]
pub(super) enum Phase {
    Access,
    Integrity,
}

impl Phase {
    pub(super) fn tag(self) -> [u8; 4] {
        match self {
            Self::Access => *b"ACL1",
            Self::Integrity => *b"LOW1",
        }
    }
}

type Query = unsafe extern "system" fn(i32, *mut c_void, u32, *mut u32) -> i32;

/// A missing API, a filtered inventory, or an incomplete record cannot confirm isolation.
pub(super) fn current_ids() -> io::Result<Vec<u32>> {
    // SAFETY: these are the IDs of the current process and thread.
    let (process, caller) = unsafe { (GetCurrentProcessId(), GetCurrentThreadId()) };
    inventory(process, Some(caller))
}

/// Query the target in the observer's security context. A worker checks its own caller ID.
pub(super) fn inventory(process: u32, caller: Option<u32>) -> io::Result<Vec<u32>> {
    // SAFETY: ntdll is already loaded for the lifetime of the process. A lookup neither
    // searches for a DLL nor takes ownership of the module.
    let module = unsafe { GetModuleHandleW(w!("ntdll.dll")) };
    if module.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: winternl.h declares this export with the Query signature. Resolve it at run
    // time so a system without the API can report an unknown outcome.
    let query: Query = unsafe {
        let entry = GetProcAddress(module, c"NtQuerySystemInformation".as_ptr().cast())
            .ok_or_else(io::Error::last_os_error)?;
        std::mem::transmute(entry)
    };
    let mut words = Vec::<u64>::new();
    let mut needed = 64 * 1024;
    while needed <= MAX_BYTES {
        let count = needed.div_ceil(size_of::<u64>());
        words
            .try_reserve_exact(count - words.len())
            .map_err(io::Error::other)?;
        words.resize(count, 0);
        let capacity = count * size_of::<u64>();
        let mut used = 0;
        // SAFETY: words is aligned, writable and initialized for exactly capacity bytes.
        let status = unsafe {
            query(
                PROCESS_INFORMATION,
                words.as_mut_ptr().cast(),
                capacity as u32,
                &mut used,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            // More processes may have started since the kernel measured the reply.
            needed = (used as usize).max(capacity * 2);
            continue;
        }
        if status != STATUS_SUCCESS {
            return Err(io::Error::other(format!(
                "NtQuerySystemInformation status {status:#x}"
            )));
        }
        if used as usize > capacity {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // SAFETY: used fits the initialized allocation. Treat it as bytes without following
        // any pointer advertised in a system record.
        let bytes = unsafe { slice::from_raw_parts(words.as_ptr().cast::<u8>(), used as usize) };
        return own_threads(bytes, process, caller).ok_or(io::ErrorKind::InvalidData.into());
    }
    Err(io::ErrorKind::FileTooLarge.into())
}

/// Read the serving thread through its pseudo handle and a live sibling through the
/// handle acquired before hardening. A live thread still owns its ID. If the old
/// handle has become signalled, the caller checks the current object afresh.
pub(super) fn pinned_integrity(
    id: u32,
    pinned: &mut super::BTreeMap<u32, super::OwnedHandle>,
) -> Option<crate::Outcome> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, WaitForSingleObject};
    // SAFETY: the pseudo handle identifies the current thread regardless of its ACL.
    let (caller, current) = unsafe { (GetCurrentThreadId(), GetCurrentThread()) };
    if id == caller {
        pinned.remove(&id);
        return Some(super::thread_integrity(current));
    }
    let handle = pinned.get(&id)?.as_raw_handle().cast();
    // SAFETY: the map owns the handle, and a zero timeout never blocks.
    if unsafe { WaitForSingleObject(handle, 0) } != WAIT_TIMEOUT {
        return None;
    }
    let level = super::thread_integrity(handle);
    pinned.remove(&id);
    Some(level)
}

fn field<const N: usize>(record: &[u8], offset: usize) -> Option<[u8; N]> {
    record.get(offset..)?.first_chunk::<N>().copied()
}

fn own_threads(mut remaining: &[u8], process: u32, caller: Option<u32>) -> Option<Vec<u32>> {
    type Process = SYSTEM_PROCESS_INFORMATION;
    type Thread = SYSTEM_THREAD_INFORMATION;
    const CLIENT: usize = offset_of!(Thread, ClientId);
    loop {
        let header = remaining.get(..size_of::<Process>())?;
        let next =
            u32::from_ne_bytes(field(header, offset_of!(Process, NextEntryOffset))?) as usize;
        let pid = usize::from_ne_bytes(field(header, offset_of!(Process, UniqueProcessId))?);
        let length = if next == 0 { remaining.len() } else { next };
        let record = remaining.get(..length)?;
        let payload = record.get(size_of::<Process>()..)?;
        if pid == process as usize {
            let count =
                u32::from_ne_bytes(field(header, offset_of!(Process, NumberOfThreads))?) as usize;
            if count == 0 || count > MAX_THREADS {
                return None;
            }
            let entries = payload.get(..count.checked_mul(size_of::<Thread>())?)?;
            let mut ids = Vec::new();
            ids.try_reserve_exact(count).ok()?;
            for entry in entries.as_chunks::<{ size_of::<Thread>() }>().0 {
                let owner = usize::from_ne_bytes(field(
                    entry,
                    CLIENT + offset_of!(CLIENT_ID, UniqueProcess),
                )?);
                let id = usize::from_ne_bytes(field(
                    entry,
                    CLIENT + offset_of!(CLIENT_ID, UniqueThread),
                )?);
                if owner != pid || id == 0 {
                    return None;
                }
                ids.push(u32::try_from(id).ok()?);
            }
            ids.sort_unstable();
            return (caller.is_none_or(|id| ids.binary_search(&id).is_ok())
                && !ids.windows(2).any(|pair| pair[0] == pair[1]))
            .then_some(ids);
        }
        if next == 0 {
            return None;
        }
        remaining = remaining.get(next..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_integrity_requires_a_complete_thread_list() {
        // Isolate a fresh test process: the primary token change affects every thread.
        const ROLE: &str = "SPC_TEST_THREAD_INVENTORY";
        const TEST: &str =
            "os::windows::threads::tests::standalone_integrity_requires_a_complete_thread_list";
        if std::env::var_os(ROLE).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(ROLE, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let (ready, ids) = std::sync::mpsc::sync_channel(0);
        let (finish, wait) = std::sync::mpsc::channel::<()>();
        let sibling = std::thread::spawn(move || {
            // SAFETY: obtains this thread's ID, valid until the parent releases it.
            ready.send(unsafe { GetCurrentThreadId() }).unwrap();
            wait.recv().unwrap();
        });
        let id = ids.recv().unwrap();
        assert!(current_ids().unwrap().contains(&id));
        let report = crate::Isolation::enter();
        match current_ids() {
            Ok(observed) => {
                assert!(observed.contains(&id));
                assert!(report.low_integrity, "{report:?}");
            }
            Err(_) => {
                assert_eq!(
                    report.outcome(crate::Protection::LowIntegrity),
                    crate::Outcome::Unknown
                );
                assert!(report.require(&[crate::Protection::LowIntegrity]).is_err());
            }
        }
        finish.send(()).unwrap();
        sibling.join().unwrap();
    }

    /// Keep a genuine above-low impersonation token active across both snapshots.
    /// The unconfined parent reads each roster using the same kernel query as Worker.
    #[test]
    fn parent_observation_detects_an_impersonating_sibling() {
        use crate::{Options, Outcome, Protection};
        use std::io::{BufRead, Write};
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::process::{Command, Stdio};
        use windows_sys::Win32::Security::TOKEN_QUERY;
        use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, GetCurrentThread, OpenProcessToken,
        };
        const ROLE: &str = "SPC_TEST_PARENT_CENSUS";
        const TEST: &str =
            "os::windows::threads::tests::parent_observation_detects_an_impersonating_sibling";
        if std::env::var_os(ROLE).is_none() {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(ROLE, "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut passes = 0;
            for line in io::BufReader::new(child.stdout.take().unwrap()).lines() {
                if line.unwrap().contains("SPC_REQUEST_THREAD_LIST") {
                    let ids = inventory(child.id(), None).unwrap();
                    assert!(ids.len() >= 2);
                    for id in ids {
                        write!(input, "{id} ").unwrap();
                    }
                    writeln!(input).unwrap();
                    input.flush().unwrap();
                    passes += 1;
                }
            }
            assert!(child.wait().unwrap().success());
            assert_eq!(passes, 2);
            return;
        }
        let mut token = std::ptr::null_mut();
        // SAFETY: open this process's primary token for metadata before lowering it.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        assert_ne!(opened, 0);
        // SAFETY: OpenProcessToken returned a new owned handle.
        let primary = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
        let (ready, running) = std::sync::mpsc::sync_channel(0);
        let (finish, wait) = std::sync::mpsc::channel();
        let sibling = std::thread::spawn(move || {
            // SAFETY: this thread borrows its own identity and reads its effective level.
            unsafe {
                assert_ne!(ImpersonateSelf(SecurityImpersonation), 0);
                assert_eq!(
                    super::super::thread_integrity(GetCurrentThread()),
                    Outcome::Refused
                );
            }
            ready.send(()).unwrap();
            wait.recv().unwrap();
            // SAFETY: the calling thread still holds the impersonation token checked above.
            let level = unsafe { super::super::thread_integrity(GetCurrentThread()) };
            assert_eq!(level, Outcome::Refused);
            // SAFETY: restore the identity on the same thread which set it.
            assert_ne!(unsafe { RevertToSelf() }, 0);
        });
        running.recv().unwrap();
        let report = super::super::enter_with_census(Options::new(), |_| {
            writeln!(io::stdout(), "SPC_REQUEST_THREAD_LIST")?;
            io::stdout().flush()?;
            let mut reply = String::new();
            io::stdin().read_line(&mut reply)?;
            let ids = reply
                .split_whitespace()
                .map(str::parse)
                .collect::<Result<Vec<u32>, _>>()
                .unwrap();
            Ok::<_, io::Error>(Some(ids))
        })
        .unwrap();
        assert!(
            super::super::integrity_of(primary.as_raw_handle().cast())
                .is_some_and(|rid| rid <= super::super::LOW_INTEGRITY_RID)
        );
        finish.send(()).unwrap();
        sibling.join().unwrap();
        assert_eq!(report.outcome(Protection::LowIntegrity), Outcome::Refused);
        assert!(report.require(&[Protection::LowIntegrity]).is_err());
    }

    #[test]
    fn only_a_complete_thread_list_containing_the_caller_is_accepted() {
        type P = SYSTEM_PROCESS_INFORMATION;
        type T = SYSTEM_THREAD_INFORMATION;
        let mut data = vec![0u8; size_of::<P>() + size_of::<T>() * 2];
        let pid = 45usize;
        data[offset_of!(P, UniqueProcessId)..][..size_of::<usize>()]
            .copy_from_slice(&pid.to_ne_bytes());
        data[offset_of!(P, NumberOfThreads)..][..4].copy_from_slice(&2u32.to_ne_bytes());
        for (index, tid) in [81usize, 82].into_iter().enumerate() {
            let client = size_of::<P>() + index * size_of::<T>() + offset_of!(T, ClientId);
            data[client + offset_of!(CLIENT_ID, UniqueProcess)..][..size_of::<usize>()]
                .copy_from_slice(&pid.to_ne_bytes());
            data[client + offset_of!(CLIENT_ID, UniqueThread)..][..size_of::<usize>()]
                .copy_from_slice(&tid.to_ne_bytes());
        }
        assert_eq!(own_threads(&data, 45, Some(82)), Some(vec![81, 82]));
        assert_eq!(own_threads(&data[..data.len() - 1], 45, Some(82)), None);
        assert_eq!(own_threads(&data, 45, Some(83)), None);
        let second = size_of::<P>()
            + size_of::<T>()
            + offset_of!(T, ClientId)
            + offset_of!(CLIENT_ID, UniqueThread);
        data[second..][..size_of::<usize>()].copy_from_slice(&81usize.to_ne_bytes());
        assert_eq!(own_threads(&data, 45, Some(81)), None);
        data[offset_of!(P, NextEntryOffset)..][..4].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(own_threads(&data, 99, Some(81)), None);
    }
}
