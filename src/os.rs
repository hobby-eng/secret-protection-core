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

#[cfg(target_vendor = "apple")]
pub(crate) use apple::{enter, measure};
#[cfg(not(any(unix, windows)))]
pub(crate) use heap::Pages;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::{enter, measure};
#[cfg(unix)]
pub(crate) use unix::{
    WorkerProcess, close_inherited, open_channels, run_on_stack, worker_streams, write_secret,
};
#[cfg(not(any(unix, windows)))]
pub(crate) use unsupported::{
    WorkerProcess, close_inherited, open_channels, run_on_stack, worker_streams,
};
#[cfg(windows)]
pub(crate) use windows::{
    WorkerProcess, close_inherited, enter, measure, open_channels, run_on_stack, worker_streams,
    write_secret,
};

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
pub(crate) fn measure(_protection: crate::Protection) -> (bool, &'static str) {
    (true, "nothing is offered on this system")
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
    #[cfg(any(unix, windows))]
    start: std::ptr::NonNull<u8>,
    #[cfg(any(unix, windows))]
    bytes: usize,
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
        // SAFETY: the pages hold `bytes` initialized bytes (the system fills them with zeros),
        // belong to this value alone and live as long as it.
        unsafe { std::slice::from_raw_parts(self.start.as_ptr(), self.bytes) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as for `as_slice`; the exclusive borrow of `self` rules out any other access.
        unsafe { std::slice::from_raw_parts_mut(self.start.as_ptr(), self.bytes) }
    }

    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }

    pub(crate) fn region(&self) -> Region {
        Region {
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

/// Where no process can be started, as in WebAssembly: no worker.
#[cfg(not(any(unix, windows)))]
mod unsupported {
    use std::io;

    pub(crate) struct WorkerProcess {
        pub(crate) to: Option<io::Sink>,
        pub(crate) from: io::Empty,
    }

    impl WorkerProcess {
        pub(crate) fn start(_options: u32, _terminal: bool) -> io::Result<Self> {
            Err(io::ErrorKind::Unsupported.into())
        }

        pub(crate) fn finish(&mut self) {
            self.to = None;
        }
    }

    pub(crate) fn close_inherited() {}

    pub(crate) fn open_channels() -> Option<Vec<crate::Channel>> {
        None
    }

    pub(crate) fn run_on_stack<R>(
        _bytes: usize,
        _work: impl FnOnce() -> R,
    ) -> io::Result<(R, bool)> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub(crate) fn worker_streams() -> (io::Empty, io::Sink) {
        (io::empty(), io::sink())
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

        pub(crate) fn work_area(bytes: usize) -> Option<Self> {
            Some(Self::new(bytes))
        }

        pub(crate) fn as_slice(&self) -> &[u8] {
            &self.0
        }

        pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.0
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
