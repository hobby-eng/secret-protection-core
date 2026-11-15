//! A process-local thread inventory remains available when system-wide enumeration is filtered.

use std::mem::size_of;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::ProcessSnapshotting::{
    HPSS, HPSSWALK, PSS_CAPTURE_THREADS, PSS_THREAD_ENTRY, PSS_WALK_THREADS, PssCaptureSnapshot,
    PssFreeSnapshot, PssWalkMarkerCreate, PssWalkMarkerFree, PssWalkSnapshot,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId,
};

/// Request only thread records from our own process. An empty or interrupted walk cannot
/// establish process-wide scope. The calling thread must be present in a complete snapshot.
pub(super) fn current_ids() -> Option<Vec<u32>> {
    // SAFETY: this process pseudo-handle stays valid for both capture and cleanup.
    let process = unsafe { GetCurrentProcess() };
    let mut snapshot = ptr::null_mut();
    // SAFETY: snapshot is writable. No thread contexts, pages or handles are requested.
    if unsafe { PssCaptureSnapshot(process, PSS_CAPTURE_THREADS, 0, &mut snapshot) }
        != ERROR_SUCCESS
    {
        return None;
    }
    let mut marker = ptr::null_mut();
    // SAFETY: a null allocator selects the system allocator, and marker is writable.
    let created = unsafe { PssWalkMarkerCreate(ptr::null(), &mut marker) };
    let ids = if created == ERROR_SUCCESS {
        let ids = walk(snapshot, marker);
        // SAFETY: the walk has finished and this call owns the marker.
        unsafe { PssWalkMarkerFree(marker) };
        ids
    } else {
        None
    };
    // SAFETY: the marker is gone and this call owns the snapshot of this process.
    unsafe { PssFreeSnapshot(process, snapshot) };
    ids
}

fn walk(snapshot: HPSS, marker: HPSSWALK) -> Option<Vec<u32>> {
    // SAFETY: both IDs belong to this caller and remain valid throughout the walk.
    let (process, caller) = unsafe { (GetCurrentProcessId(), GetCurrentThreadId()) };
    let mut ids = Vec::new();
    loop {
        let mut entry = PSS_THREAD_ENTRY::default();
        // SAFETY: the marker and snapshot are live. The writable buffer has the layout
        // and size required for a thread entry. No pointers from the entry are used.
        let status = unsafe {
            PssWalkSnapshot(
                snapshot,
                PSS_WALK_THREADS,
                marker,
                (&raw mut entry).cast(),
                size_of::<PSS_THREAD_ENTRY>() as u32,
            )
        };
        match status {
            ERROR_SUCCESS if entry.ProcessId == process => ids.push(entry.ThreadId),
            ERROR_NO_MORE_ITEMS if ids.contains(&caller) => return Some(ids),
            _ => return None,
        }
    }
}
