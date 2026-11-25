//! System calls behind [`crate::protect`], one module per system. [`Pages`] is the memory of one
//! secret or work area; each module maps, locks and frees it, and applies the isolation.

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
pub(crate) use apple::listed_access;
#[cfg(target_vendor = "apple")]
pub(crate) use apple::{enter_granting, evidence, shared_mappings};
#[cfg(not(any(unix, windows)))]
pub(crate) use heap::Pages;
#[cfg(target_os = "linux")]
pub(crate) use linux::one_thread;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::{enter_granting, evidence, shared_mappings};
#[cfg(unix)]
pub(crate) use unix::{
    HiddenTerminal, WorkerProcess, leave_terminal, open_channels, run_on_stack, starts_clean,
    worker_streams, write_secret,
};
#[cfg(not(any(unix, windows)))]
pub(crate) use unsupported::{
    WorkerProcess, leave_terminal, open_channels, run_on_stack, starts_clean, worker_streams,
};
#[cfg(windows)]
pub(crate) use windows::{
    HiddenTerminal, WorkerProcess, enter, evidence, leave_terminal, open_channels, run_on_stack,
    starts_clean, worker_streams, write_secret,
};

/// The isolation without folders to write in.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
pub(crate) fn enter(options: crate::protect::Options) -> crate::protect::Isolation {
    enter_granting(options, &[])
}

/// Other Unix systems have no way here to list shared memory: the channel check stays incomplete.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
pub(crate) fn shared_mappings() -> Option<Vec<crate::SharedMapping>> {
    None
}

/// Other Unix systems apply no isolation, so they grant no folder either.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
pub(crate) fn enter_granting(
    options: crate::protect::Options,
    _folders: &[&crate::WritableFolder],
) -> crate::protect::Isolation {
    enter(options)
}

/// How long a worker gets to end by itself once its pipes are closed, and again once it was
/// killed.
#[cfg(any(unix, windows))]
const GRACE: std::time::Duration = std::time::Duration::from_secs(1);
/// How long a wait for a worker or for its pipe pauses before it looks again.
#[cfg(windows)]
const STEP: std::time::Duration = std::time::Duration::from_millis(2);

/// Where this crate knows no protection of the process, as in WebAssembly, it applies none.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
pub(crate) fn enter(_options: crate::protect::Options) -> crate::protect::Isolation {
    crate::protect::Isolation::default()
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
pub(crate) fn evidence(
    _protection: crate::Protection,
    _outcome: crate::Outcome,
) -> Option<&'static str> {
    None
}

#[cfg(all(test, unix))]
thread_local! {
    /// How many changes of access the tests have still to see refused on this thread.
    static REFUSALS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Fault: the next `count` changes of access on this thread are refused, as the system refuses
/// `mprotect` under a policy or without memory. No input causes that, so the tests ask for it.
#[cfg(all(test, unix))]
pub(crate) fn refuse_changes(count: u32) {
    REFUSALS.set(count);
}

/// Whether a test asked for this change of access to be refused.
#[cfg(all(test, unix))]
fn refused_for_a_test() -> bool {
    let left = REFUSALS.get();
    REFUSALS.set(left.saturating_sub(1));
    left > 0
}

/// What a program may do with pages: nothing, read them, or read and write them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    Nothing,
    Read,
    ReadWrite,
}

/// Where some [`Pages`] lie, to open or close them apart from their owner, whatever borrows
/// their bytes meanwhile.
#[derive(Clone, Copy)]
pub(crate) struct Region {
    #[cfg(unix)]
    generation: usize,
    #[cfg(any(unix, windows))]
    start: std::ptr::NonNull<u8>,
    #[cfg(any(unix, windows))]
    bytes: usize,
}

/// Wipes `bytes` bytes from `start` without reading them: a stack leaves bytes that were never
/// written, which no `u8` may stand for.
///
/// # Safety
/// The bytes must be writable and nothing else may refer to them during the call.
#[cfg(any(unix, test))]
#[allow(unsafe_code, reason = "the bytes are reached through a raw pointer")]
unsafe fn wipe_unwritten(start: *mut u8, bytes: usize) {
    use zeroize::Zeroize;
    // SAFETY: the caller's promise; `MaybeUninit<u8>` is valid for every byte, written or not.
    let region =
        unsafe { std::slice::from_raw_parts_mut(start.cast::<std::mem::MaybeUninit<u8>>(), bytes) };
    region.zeroize();
}

/// Pages that a system's module mapped: `bytes` bytes from `start`, which belong to this value
/// alone.
#[cfg(any(unix, windows))]
pub(crate) struct Pages {
    start: std::ptr::NonNull<u8>,
    bytes: usize,
    locked: bool,
    /// Whether the pages are left out of core dumps.
    #[cfg(unix)]
    out_of_dumps: bool,
    /// Whether a child process gets none of the bytes: no mapping, or zeros.
    #[cfg(unix)]
    out_of_children: bool,
    /// The forks counted when the pages were made: in a child of a later `fork` the count is
    /// higher, and the pages are not there to use.
    #[cfg(unix)]
    generation: usize,
    /// The blocks registered with Windows Error Reporting, which holds 512 per process.
    #[cfg(windows)]
    excluded: usize,
    /// What the working set grew by for these pages alone, given back on drop.
    #[cfg(windows)]
    raised: usize,
}

#[cfg(any(unix, windows))]
#[allow(
    unsafe_code,
    reason = "the mapped pages are reached through a raw pointer"
)]
impl Pages {
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.check();
        // SAFETY: the pages hold `bytes` initialized bytes (the system fills them with zeros),
        // belong to this value alone and live as long as it; `check` ended a child of `fork`.
        unsafe { std::slice::from_raw_parts(self.start.as_ptr(), self.bytes) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.check();
        // SAFETY: as for `as_slice`; the exclusive borrow of `self` rules out any other access.
        unsafe { std::slice::from_raw_parts_mut(self.start.as_ptr(), self.bytes) }
    }

    pub(crate) fn is_locked(&self) -> bool {
        self.locked && self.here()
    }

    /// Whether this process allocated the pages. Ordinary Unix `fork` advances the child's
    /// generation even when the OS could not exclude the contents.
    pub(crate) fn here(&self) -> bool {
        #[cfg(unix)]
        let here = self.generation == unix::forks::generation();
        #[cfg(windows)]
        let here = true;
        here
    }

    /// Ends a child of `fork` that reaches its parent's pages, before any reference to them.
    fn check(&self) {
        #[cfg(unix)]
        if !self.here() {
            unix::forks::foreign();
        }
    }

    /// Wipes the pages whatever they hold, as a thread's stack leaves them.
    #[cfg(unix)]
    pub(crate) fn wipe_any(&mut self) {
        if self.here() {
            // SAFETY: the pages belong to this value alone and are mapped for `bytes` bytes.
            unsafe { wipe_unwritten(self.start.as_ptr(), self.bytes) };
        }
    }

    pub(crate) fn region(&self) -> Region {
        self.check();
        Region {
            #[cfg(unix)]
            generation: self.generation,
            start: self.start,
            bytes: self.bytes,
        }
    }
}

#[cfg(any(unix, windows))]
#[allow(
    unsafe_code,
    reason = "a raw pointer is neither Send nor Sync by itself"
)]
// SAFETY: the pages belong to one value; moving it to another thread moves the only handle, and
// a shared reference only reads them.
unsafe impl Send for Pages {}
#[cfg(any(unix, windows))]
#[allow(
    unsafe_code,
    reason = "a raw pointer is neither Send nor Sync by itself"
)]
// SAFETY: as for `Send`.
unsafe impl Sync for Pages {}

/// Ends the process as a full heap does, for pages the system cannot give.
#[cfg(any(unix, windows))]
fn out_of_memory(bytes: usize) -> ! {
    let layout = std::alloc::Layout::array::<u8>(bytes).unwrap_or(std::alloc::Layout::new::<u8>());
    std::alloc::handle_alloc_error(layout)
}

/// Where no process can be started, as in WebAssembly: no worker, no list of channels, no stack.
#[cfg(not(any(unix, windows)))]
mod unsupported {
    use std::io;

    pub(crate) struct WorkerProcess {
        pub(crate) to: Option<io::Sink>,
        pub(crate) from: Option<io::Empty>,
    }

    impl WorkerProcess {
        pub(crate) fn start(
            _setting: &str,
            _terminal: bool,
            _deadline: Option<std::time::Instant>,
        ) -> io::Result<Self> {
            Err(io::ErrorKind::Unsupported.into())
        }

        pub(crate) fn close(&mut self) {
            self.to = None;
            self.from = None;
        }

        pub(crate) fn exchanging<T>(
            &mut self,
            deadline: Option<std::time::Instant>,
            work: impl FnOnce(&mut Self, Option<std::time::Instant>) -> io::Result<T>,
        ) -> io::Result<T> {
            work(self, deadline)
        }

        pub(crate) fn read_exact_until(
            &mut self,
            buffer: &mut [u8],
            _deadline: Option<std::time::Instant>,
        ) -> io::Result<()> {
            use std::io::Read;
            let from = self.from.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
            from.read_exact(buffer)
        }

        pub(crate) fn write_all_until(
            &mut self,
            data: &[u8],
            _deadline: Option<std::time::Instant>,
        ) -> io::Result<()> {
            use std::io::Write;
            let to = self.to.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
            to.write_all(data)
        }

        pub(crate) fn finish(&mut self) -> bool {
            self.close();
            true
        }
    }

    pub(crate) fn starts_clean() -> bool {
        true
    }

    pub(crate) fn leave_terminal() -> bool {
        true
    }

    pub(crate) fn open_channels() -> io::Result<crate::OpenChannels> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub(crate) fn run_on_stack<R>(
        _bytes: usize,
        _required: crate::StackProperties,
        _work: impl FnOnce() -> R,
    ) -> Result<(R, crate::StackProperties), crate::StackError> {
        Err(crate::StackError::Unsupported)
    }

    /// No worker starts here: its streams give nothing and take nothing.
    pub(crate) struct WorkerStreams;

    impl io::Read for WorkerStreams {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl io::Write for WorkerStreams {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn worker_streams(_channel: &str) -> io::Result<WorkerStreams> {
        Ok(WorkerStreams)
    }
}

/// Where there are no pages to ask for, such as in WebAssembly: an ordinary heap buffer, wiped
/// like the others but never locked or kept out of anything.
#[cfg(not(any(unix, windows)))]
mod heap {
    pub(crate) struct Pages(Box<[u8]>);

    impl Pages {
        pub(crate) fn new(bytes: usize) -> Self {
            Self(vec![0; bytes].into_boxed_slice())
        }

        /// `None` when the allocator has no such buffer, where `new` would end the program.
        pub(crate) fn work_area(bytes: usize) -> Option<Self> {
            let mut area = Vec::new();
            area.try_reserve_exact(bytes).ok()?;
            area.resize(bytes, 0);
            Some(Self(area.into_boxed_slice()))
        }

        pub(crate) fn as_slice(&self) -> &[u8] {
            &self.0
        }

        pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.0
        }

        /// No process starts here, so no buffer is another's.
        pub(crate) fn here(&self) -> bool {
            true
        }

        pub(crate) fn is_locked(&self) -> bool {
            false
        }

        pub(crate) fn is_out_of_dumps(&self) -> bool {
            false
        }

        pub(crate) fn is_out_of_children(&self) -> bool {
            false
        }

        pub(crate) fn region(&self) -> super::Region {
            super::Region {}
        }
    }

    impl super::Region {
        /// A heap buffer cannot be closed.
        pub(crate) fn allow(self, _access: super::Access) -> bool {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn a_foreign_region_cannot_change_page_permissions() {
        let mut pages = super::Pages::new(1);
        let mut stale = pages.region();
        stale.generation = stale.generation.wrapping_add(1);
        assert!(!stale.allow(super::Access::Nothing));
        pages.as_mut_slice()[0] = 42;
        assert_eq!(pages.as_slice(), [42]);
    }

    /// Memory that was never written is wiped whole. Miri runs this check too and would stop at
    /// a read of an unwritten byte.
    #[test]
    #[allow(unsafe_code, reason = "the wipe takes a raw pointer")]
    fn unwritten_bytes_are_wiped_without_being_read() {
        let mut block = Box::<[u8]>::new_uninit_slice(4096);
        // SAFETY: the block is allocated for its length and nothing else refers to it.
        unsafe { super::wipe_unwritten(block.as_mut_ptr().cast(), block.len()) };
        // SAFETY: the wipe wrote every byte.
        let block = unsafe { block.assume_init() };
        assert!(block.iter().all(|&byte| byte == 0));
    }
}
