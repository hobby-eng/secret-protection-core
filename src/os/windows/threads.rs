//! Read the calling process's thread records from the kernel's process inventory.
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
type Query = unsafe extern "system" fn(i32, *mut c_void, u32, *mut u32) -> i32;

/// A missing API, a filtered inventory, or an incomplete record cannot confirm isolation.
pub(super) fn current_ids() -> io::Result<Vec<u32>> {
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
        // SAFETY: these are the caller's process and thread IDs.
        let (process, caller) = unsafe { (GetCurrentProcessId(), GetCurrentThreadId()) };
        return own_threads(bytes, process, caller)
            .ok_or_else(|| io::ErrorKind::InvalidData.into());
    }
    Err(io::ErrorKind::FileTooLarge.into())
}

fn field<const N: usize>(record: &[u8], offset: usize) -> Option<[u8; N]> {
    record.get(offset..)?.first_chunk::<N>().copied()
}

fn own_threads(mut remaining: &[u8], process: u32, caller: u32) -> Option<Vec<u32>> {
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
            return (ids.binary_search(&caller).is_ok()
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
    fn live_threads_are_visible_after_lowering_integrity() {
        // Isolate a fresh test process: the primary token change affects every thread.
        const ROLE: &str = "SPC_TEST_THREAD_INVENTORY";
        const TEST: &str =
            "os::windows::threads::tests::live_threads_are_visible_after_lowering_integrity";
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
        let observed = current_ids().expect("read process and thread records after isolation");
        assert!(observed.contains(&id) && report.low_integrity, "{report:?}");
        finish.send(()).unwrap();
        sibling.join().unwrap();
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
        assert_eq!(own_threads(&data, 45, 82), Some(vec![81, 82]));
        assert_eq!(own_threads(&data[..data.len() - 1], 45, 82), None);
        assert_eq!(own_threads(&data, 45, 83), None);
        let second = size_of::<P>()
            + size_of::<T>()
            + offset_of!(T, ClientId)
            + offset_of!(CLIENT_ID, UniqueThread);
        data[second..][..size_of::<usize>()].copy_from_slice(&81usize.to_ne_bytes());
        assert_eq!(own_threads(&data, 45, 81), None);
        data[offset_of!(P, NextEntryOffset)..][..4].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(own_threads(&data, 99, 81), None);
    }
}
