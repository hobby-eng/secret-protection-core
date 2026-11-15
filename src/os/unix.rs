//! Unix pages for secrets: anonymous mappings with `mlock`, between guard pages, kept out of core
//! dumps and child processes where the system allows. Also the core-dump limit, starting a worker
//! and the secret writer.
#![allow(
    unsafe_code,
    reason = "mmap, mprotect, mlock, getrlimit, setrlimit, madvise, minherit, munmap, sysconf and \
              write are foreign functions"
)]

use std::fs::File;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::ptr::{self, NonNull};

use super::{Access, Pages, Region};

impl Pages {
    /// `bytes` bytes, at least one, in pages of their own.
    pub(crate) fn new(bytes: usize) -> Self {
        #[cfg(target_os = "linux")]
        if let Some(start) = super::linux::secret_pages(bytes) {
            // Secret memory stays out of swap and core dumps by construction, which is what
            // `locked` promises: on a newer kernel the mapping itself carries no lock.
            // `secret_pages` keeps the mapping out of a child process (MADV_DONTFORK) or gives it
            // back.
            return Self {
                start,
                bytes,
                locked: true,
                out_of_dumps: true,
                out_of_children: true,
            };
        }
        Self::anonymous(bytes, true).unwrap_or_else(|| super::out_of_memory(bytes))
    }

    /// The work area of a computation: anonymous pages as for a secret, never secret memory, or `None`
    /// when the system refuses them. They are locked only when RLIMIT_MEMLOCK holds all of them,
    /// which also commits them; a refused lock leaves them as they are.
    pub(crate) fn work_area(bytes: usize) -> Option<Self> {
        Self::anonymous(bytes, lock_limit_holds(bytes))
    }

    fn anonymous(bytes: usize, lock: bool) -> Option<Self> {
        let start = reserve(bytes)?;
        // SAFETY: opens for reading and writing the pages between the guards of the reservation
        // just made, which nothing else refers to; they are zero.
        if unsafe {
            libc::mprotect(
                start.as_ptr().cast(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            release(start, bytes);
            return None;
        }
        // SAFETY: mlock only changes how the kernel keeps the pages of the mapping just made; a
        // refusal, such as beyond RLIMIT_MEMLOCK, leaves them as they are.
        let locked = lock && unsafe { libc::mlock(start.as_ptr().cast(), bytes) } == 0;
        let (out_of_dumps, out_of_children) = advise(start, bytes);
        Some(Self {
            start,
            bytes,
            locked,
            out_of_dumps,
            out_of_children,
        })
    }

    pub(crate) fn is_out_of_dumps(&self) -> bool {
        self.out_of_dumps
    }

    pub(crate) fn is_out_of_children(&self) -> bool {
        self.out_of_children
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        // Unmapping the pages also unlocks them.
        release(self.start, self.bytes);
    }
}

impl Region {
    /// Lets the pages be reached as `access` says, and returns whether the system agreed.
    pub(crate) fn allow(self, access: Access) -> bool {
        let protection = match access {
            Access::Nothing => libc::PROT_NONE,
            Access::Read => libc::PROT_READ,
            Access::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
        };
        // SAFETY: changes the protection of pages a `Pages` of this crate owns; the caller makes
        // no reference to them while they refuse it.
        unsafe { libc::mprotect(self.start.as_ptr().cast(), self.bytes, protection) == 0 }
    }
}

/// The size of a memory page.
fn page_size() -> usize {
    // SAFETY: sysconf takes an integer and touches no memory of this process.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(page).unwrap_or(4096)
}

/// Reserves pages for `bytes` bytes between two guard pages, every page refusing every access, and
/// returns where the bytes go: past the first guard. A run past either end of the pages then
/// faults instead of reaching other memory; one within the last page, past `bytes`, does not.
pub(super) fn reserve(bytes: usize) -> Option<NonNull<u8>> {
    let page = page_size();
    let total = bytes
        .checked_next_multiple_of(page)?
        .checked_add(2 * page)?;
    // SAFETY: a new private anonymous mapping that refuses every access, at an address the kernel
    // chooses, takes no memory that anything else owns.
    let mapped = unsafe {
        libc::mmap(
            ptr::null_mut(),
            total,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return None;
    }
    NonNull::new(mapped.cast::<u8>().wrapping_add(page))
}

/// Gives back the pages that [`reserve`] reserved for `bytes` bytes at `start`, guards included,
/// whatever was mapped between them.
pub(super) fn release(start: NonNull<u8>, bytes: usize) {
    let page = page_size();
    let total = bytes.next_multiple_of(page) + 2 * page;
    // SAFETY: the reservation belongs to the caller alone and nothing borrows it any more.
    unsafe { libc::munmap(start.as_ptr().wrapping_sub(page).cast(), total) };
}

/// Whether RLIMIT_MEMLOCK lets this process lock `bytes` bytes, counted alone.
fn lock_limit_holds(bytes: usize) -> bool {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the limit into the struct it is given.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } == 0;
    // RLIM_INFINITY is the largest value, so no size exceeds it.
    read && libc::rlim_t::try_from(bytes).is_ok_and(|bytes| bytes <= limit.rlim_cur)
}

/// Keeps the pages out of core dumps and gives a child process zeros instead of them (Linux 4.14
/// and later; an older kernel refuses, and the refusal is reported). Returns whether the dump
/// exclusion holds and whether a child process gets zeros.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn advise(start: NonNull<u8>, bytes: usize) -> (bool, bool) {
    // Never merged with a page of the same content elsewhere, should a parent have asked the
    // kernel to merge every page of the process (PR_SET_MEMORY_MERGE, which a child inherits):
    // the time a write takes would tell a merged page. A kernel without KSM refuses, which leaves
    // nothing to merge.
    // SAFETY: madvise marks the pages of a mapping this process owns and changes no content.
    unsafe { libc::madvise(start.as_ptr().cast(), bytes, libc::MADV_UNMERGEABLE) };
    // SAFETY: as above.
    let wiped = unsafe { libc::madvise(start.as_ptr().cast(), bytes, libc::MADV_WIPEONFORK) } == 0;
    // SAFETY: as above.
    let out_of_dumps =
        unsafe { libc::madvise(start.as_ptr().cast(), bytes, libc::MADV_DONTDUMP) } == 0;
    (out_of_dumps, wiped)
}

/// Leaves the pages out of a child process, and reports whether the system agreed. No call keeps
/// single pages out of a core dump here; the process as a whole writes none once it is isolated.
#[cfg(target_vendor = "apple")]
fn advise(start: NonNull<u8>, bytes: usize) -> (bool, bool) {
    // SAFETY: minherit changes only what a child process inherits of a mapping this process owns.
    let left_out =
        unsafe { libc::minherit(start.as_ptr().cast(), bytes, libc::VM_INHERIT_NONE) } == 0;
    (false, left_out)
}

/// Other Unix systems lock the pages only.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn advise(_start: NonNull<u8>, _bytes: usize) -> (bool, bool) {
    (false, false)
}

/// The parent's end of a worker: the worker's standard input and output, and the process.
pub(crate) struct WorkerProcess {
    pub(crate) to: Option<ChildStdin>,
    pub(crate) from: ChildStdout,
    child: Child,
}

impl WorkerProcess {
    /// Starts this program again with an empty environment but the worker's variable, its standard
    /// input and output piped; without `terminal`, its standard error goes nowhere and it starts a
    /// session of its own, so that it has no controlling terminal. Android and iOS start no worker.
    pub(crate) fn start(options: u32, terminal: bool) -> io::Result<Self> {
        if cfg!(any(target_os = "android", target_os = "ios")) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let mut command = Command::new(std::env::current_exe()?);
        command
            .env_clear()
            .env(crate::worker::WORKER, options.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if terminal {
            command.stderr(Stdio::inherit());
        } else {
            command.stderr(Stdio::null());
            // SAFETY: runs in the child between fork and exec, where only async-signal-safe calls
            // are allowed; setsid is one and touches no memory.
            unsafe {
                std::os::unix::process::CommandExt::pre_exec(&mut command, || {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn()?;
        let (Some(to), Some(from)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        Ok(Self {
            to: Some(to),
            from,
            child,
        })
    }

    /// Closes the worker's input, which ends it, and waits for it.
    pub(crate) fn finish(&mut self) {
        self.to = None;
        let _ = self.child.wait();
    }
}

/// Closes every descriptor of the worker but its standard streams: whatever the program opened
/// without close-on-exec reached it. Linux closes them in one call (`close_range`, Linux 5.9);
/// otherwise each one listed in /proc/self/fd or /dev/fd.
pub(crate) fn close_inherited() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: close_range takes integers and closes descriptors that nothing in this new process
    // refers to yet, the worker calling it first.
    if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } == 0 {
        return;
    }
    let listed = if cfg!(target_vendor = "apple") {
        "/dev/fd"
    } else {
        "/proc/self/fd"
    };
    let Ok(entries) = std::fs::read_dir(listed) else {
        return;
    };
    let descriptors: Vec<i32> = entries
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|&descriptor| descriptor > 2)
        .collect();
    for descriptor in descriptors {
        // SAFETY: closes a descriptor the worker inherited, which nothing in it refers to; the
        // listing's own descriptor is closed already, and closing it again does nothing.
        unsafe { libc::close(descriptor) };
    }
}

/// The open descriptors, from /proc/self/fd (or /dev/fd on Apple systems), each judged by
/// `fstat` and its open flags. The listing's own descriptor is closed by the time they are judged,
/// so it drops out.
pub(crate) fn open_channels() -> Option<Vec<crate::Channel>> {
    use crate::ChannelKind;
    let listed = if cfg!(target_vendor = "apple") {
        "/dev/fd"
    } else {
        "/proc/self/fd"
    };
    let mut numbers: Vec<i32> = std::fs::read_dir(listed)
        .ok()?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    numbers.sort_unstable();
    let channels = numbers.into_iter().filter_map(|descriptor| {
        // SAFETY: an all-zero `stat` is valid, and fstat writes it for the descriptor or fails.
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above; fstat touches nothing else.
        if unsafe { libc::fstat(descriptor, &mut status) } != 0 {
            return None;
        }
        // SAFETY: fcntl with F_GETFL takes an integer and returns the flags.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        let writable =
            flags >= 0 && matches!(flags & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR);
        let kind = match status.st_mode & libc::S_IFMT {
            libc::S_IFSOCK => ChannelKind::Socket,
            libc::S_IFIFO => ChannelKind::Pipe,
            // SAFETY: isatty takes an integer.
            libc::S_IFCHR if unsafe { libc::isatty(descriptor) } == 1 => ChannelKind::Terminal,
            libc::S_IFDIR => ChannelKind::Other,
            _ if writable => ChannelKind::WritableFile,
            _ => ChannelKind::Other,
        };
        Some(crate::Channel { descriptor, kind })
    });
    Some(channels.collect())
}

#[cfg(not(target_vendor = "apple"))]
use libc::pthread_attr_setstack;

// libc declares it for every Unix but Apple's, whose C library has it too.
#[cfg(target_vendor = "apple")]
unsafe extern "C" {
    fn pthread_attr_setstack(
        attributes: *mut libc::pthread_attr_t,
        stack: *mut libc::c_void,
        size: libc::size_t,
    ) -> libc::c_int;
}

/// Runs `work` on a new thread whose stack is a work area of at least `bytes` (guard pages, out of
/// dumps and children, locked where the limit allows), wiped after the thread ends. glibc also puts
/// the thread's own data and static TLS at the top of a stack it is given.
pub(crate) fn run_on_stack<R: Send, F: FnOnce() -> R + Send>(
    bytes: usize,
    work: F,
) -> io::Result<(R, bool)> {
    use zeroize::Zeroize;

    struct Job<F, R> {
        work: Option<F>,
        result: Option<std::thread::Result<R>>,
    }

    extern "C" fn start<F: FnOnce() -> R, R>(job: *mut libc::c_void) -> *mut libc::c_void {
        // SAFETY: `job` is the `Job` that `run_on_stack` keeps alive until the join returns, and
        // only this thread touches it meanwhile.
        let job = unsafe { &mut *job.cast::<Job<F, R>>() };
        if let Some(work) = job.work.take() {
            job.result = Some(std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)));
        }
        ptr::null_mut()
    }

    let size = bytes
        .next_multiple_of(page_size())
        .max(libc::PTHREAD_STACK_MIN);
    let mut stack = Pages::work_area(size).ok_or(io::ErrorKind::OutOfMemory)?;
    let mut job = Job {
        work: Some(work),
        result: None,
    };
    // SAFETY: the attribute is initialized before use and destroyed once; the stack pages belong
    // to `stack`, which outlives the thread because the thread is joined before it is dropped.
    let made = unsafe {
        let mut attributes: libc::pthread_attr_t = std::mem::zeroed();
        let mut thread: libc::pthread_t = std::mem::zeroed();
        let mut made = libc::pthread_attr_init(&mut attributes);
        if made == 0 {
            made = pthread_attr_setstack(&mut attributes, stack.start.as_ptr().cast(), size);
            if made == 0 {
                made = libc::pthread_create(
                    &mut thread,
                    &attributes,
                    start::<F, R>,
                    (&raw mut job).cast(),
                );
                if made == 0 {
                    libc::pthread_join(thread, ptr::null_mut());
                }
            }
            libc::pthread_attr_destroy(&mut attributes);
        }
        made
    };
    stack.as_mut_slice().zeroize();
    if made != 0 {
        return Err(io::Error::from_raw_os_error(made));
    }
    match job.result {
        Some(Ok(value)) => Ok((value, stack.is_locked())),
        Some(Err(panic)) => std::panic::resume_unwind(panic),
        None => Err(io::Error::other("the thread did not run the work")),
    }
}

/// The worker's standard input and output, unbuffered, so that no copy of a secret stays in a
/// buffer of the standard library; they stay open when dropped.
pub(crate) fn worker_streams() -> (ManuallyDrop<File>, ManuallyDrop<File>) {
    // SAFETY: descriptors 0 and 1 are the pipes the parent made, open for the whole process;
    // `ManuallyDrop` never closes them.
    unsafe {
        (
            ManuallyDrop::new(File::from_raw_fd(libc::STDIN_FILENO)),
            ManuallyDrop::new(File::from_raw_fd(libc::STDOUT_FILENO)),
        )
    }
}

/// Sets both limits of RLIMIT_CORE to 0, so that a crash writes no core file and the limit cannot
/// be raised again, and returns whether they read back so.
pub(super) fn forbid_core_dumps() -> bool {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads the struct, which lives for the call.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: getrlimit writes the struct, which lives for the call.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } == 0;
    read && (limit.rlim_cur, limit.rlim_max) == (0, 0)
}

/// Writes `text` to descriptor 1 with `write(2)`, again after an interruption and for what a
/// partial write left.
pub(crate) fn write_secret(text: &str) -> io::Result<()> {
    let mut rest = text.as_bytes();
    while !rest.is_empty() {
        // SAFETY: write reads at most `rest.len()` bytes of `rest`, which lives for the call.
        let written = unsafe { libc::write(libc::STDOUT_FILENO, rest.as_ptr().cast(), rest.len()) };
        match usize::try_from(written) {
            // As `Write::write_all` does: a write that takes nothing would be asked again forever.
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => rest = &rest[written..],
            Err(_) => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}
