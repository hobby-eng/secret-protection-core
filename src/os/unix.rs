//! Unix pages for secrets: anonymous mappings with `mlock`, between guard pages, kept out of core
//! dumps and child processes where the system allows. Also the core-dump limit, the worker's side
//! of its start and the secret writer. The parent's side of a worker is in `worker`.
#![allow(
    unsafe_code,
    reason = "mmap, mprotect, mlock, getrlimit, setrlimit, madvise, minherit, munmap, sysconf and \
              write are foreign functions"
)]

use std::fs::File;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::ptr::{self, NonNull};

use super::{Access, Pages, Region};

mod child;
pub(super) mod forks;
mod terminal;
mod worker;

pub(crate) use terminal::HiddenTerminal;
pub(crate) use worker::WorkerProcess;

impl Pages {
    /// `bytes` bytes, at least one, in pages of their own.
    pub(crate) fn new(bytes: usize) -> Self {
        if !forks::watched() {
            super::out_of_memory(bytes);
        }
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
                generation: forks::generation(),
            };
        }
        Self::anonymous(bytes, Purpose::Secret).unwrap_or_else(|| super::out_of_memory(bytes))
    }

    /// The work area of a computation: anonymous pages as for a secret, never secret memory, or
    /// `None`
    /// when the system refuses them. They are locked only when RLIMIT_MEMLOCK holds all of them,
    /// which also commits them; a refused lock leaves them as they are.
    pub(crate) fn work_area(bytes: usize) -> Option<Self> {
        forks::watched().then(|| Self::anonymous(bytes, Purpose::Work))?
    }

    /// A protected stack: a work area on small pages, which a thread's frames, holding the
    /// secret values of its work, need no huge pages for.
    pub(crate) fn stack(bytes: usize) -> Option<Self> {
        forks::watched().then(|| Self::anonymous(bytes, Purpose::Stack))?
    }

    fn anonymous(bytes: usize, purpose: Purpose) -> Option<Self> {
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
        let lock = match purpose {
            // Before the lock, which fills the pages in.
            Purpose::Secret => {
                keep_small(start, bytes);
                true
            }
            Purpose::Work => lock_limit_holds(bytes),
            Purpose::Stack => {
                keep_small(start, bytes);
                lock_limit_holds(bytes)
            }
        };
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
            generation: forks::generation(),
        })
    }

    pub(crate) fn is_out_of_dumps(&self) -> bool {
        self.out_of_dumps && self.here()
    }

    pub(crate) fn is_out_of_children(&self) -> bool {
        self.out_of_children && self.here()
    }
}

/// What anonymous pages are for: secrets request small pages and a lock. Work areas request a lock
/// when the limit can cover them, and stacks small pages as well. Any lock request can fail.
#[derive(Clone, Copy)]
enum Purpose {
    Secret,
    Work,
    Stack,
}

impl Drop for Pages {
    fn drop(&mut self) {
        // Unmapping the pages also unlocks them. A child of `fork` leaves its parent's alone:
        // an excluded mapping's address can already belong to a new allocation.
        if self.here() {
            release(self.start, self.bytes);
        }
    }
}

impl Region {
    /// Lets the pages be reached as `access` says, and returns whether the system agreed.
    pub(crate) fn allow(self, access: Access) -> bool {
        if self.generation != forks::generation() {
            return false;
        }
        #[cfg(test)]
        if super::refused_for_a_test() {
            return false;
        }
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
pub(super) fn page_size() -> usize {
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
    #[cfg(target_os = "linux")]
    super::linux::forget_secret(start);
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

/// Asks the kernel to keep a secret or a protected stack on small pages. Joining pages into a
/// huge one copies them, and the kernel frees the old ones without wiping them. A work area keeps
/// the huge pages the system gives it: a large computation is much slower without them. A kernel
/// without huge pages refuses, which leaves nothing to join, so the answer is not read.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn keep_small(start: NonNull<u8>, bytes: usize) {
    // SAFETY: madvise marks the pages of a mapping this process owns and changes no content.
    unsafe { libc::madvise(start.as_ptr().cast(), bytes, libc::MADV_NOHUGEPAGE) };
}

/// Other systems join no pages of a program behind its back.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn keep_small(_start: NonNull<u8>, _bytes: usize) {}

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

/// Whether `descriptor` is open.
fn is_open(descriptor: i32) -> bool {
    // SAFETY: fcntl with F_GETFD takes integers and only reads.
    unsafe { libc::fcntl(descriptor, libc::F_GETFD) != -1 }
}

/// Where the system lists the open descriptors of the process.
const DESCRIPTORS: &std::ffi::CStr = if cfg!(target_vendor = "apple") {
    c"/dev/fd"
} else {
    c"/proc/thread-self/fd"
};

/// [`DESCRIPTORS`] as the path the standard library takes.
fn descriptors() -> &'static std::ffi::OsStr {
    std::ffi::OsStr::from_bytes(DESCRIPTORS.to_bytes())
}

/// The numbers of the open descriptors, the listing's own among them; `None` when the listing
/// fails or holds a name that is no number.
fn listed_descriptors() -> Option<Vec<i32>> {
    let mut numbers = Vec::new();
    for entry in std::fs::read_dir(descriptors()).ok()? {
        numbers.push(entry.ok()?.file_name().to_str()?.parse().ok()?);
    }
    Some(numbers)
}

/// Registers the fork generation handler during native startup on supported systems.
/// Initializers of other linked libraries can run before this one. No file descriptor is closed.
extern "C" fn before_main() {
    forks::watched();
}

/// Puts [`before_main`] among the functions the system runs before `main`. On Apple systems the
/// section names its kind, pointers to such functions, so that every linker keeps it one.
#[used]
#[cfg_attr(
    any(target_os = "linux", target_os = "android"),
    unsafe(link_section = ".init_array")
)]
#[cfg_attr(
    target_vendor = "apple",
    unsafe(link_section = "__DATA,__mod_init_func,mod_init_funcs")
)]
static BEFORE_MAIN: extern "C" fn() = before_main;

/// Checks the descriptor numbers visible at entry to serve. It neither inventories earlier
/// use by initializers nor verifies the identity of standard streams. On Linux this uses the
/// calling thread's descriptor table. A thread with an unshared table may hold different
/// descriptors. A failed listing rejects the startup check.
pub(crate) fn starts_clean() -> bool {
    // The listing's own descriptor takes the lowest free number, 3, and is gone with it.
    let alone = listed_descriptors().is_some_and(|open| open.iter().all(|&d| d <= 3));
    alone && !is_open(3)
}

/// Leaves the terminal the program was started on: a session of its own has no controlling
/// terminal. The worker calls it itself, first thing, so its start needs no code after `fork`.
pub(crate) fn leave_terminal() -> bool {
    // SAFETY: setsid takes nothing and touches no memory.
    unsafe { libc::setsid() >= 0 }
}

/// What looking at one descriptor gave.
enum Examined {
    Open(crate::Channel),
    /// Closed since it was listed, as the listing's own descriptor is.
    Gone,
    Failed,
}

fn examine(descriptor: i32) -> Examined {
    use crate::ChannelKind;
    // SAFETY: an all-zero `stat` is valid, and fstat writes it for the descriptor or fails.
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above; fstat touches nothing else.
    if unsafe { libc::fstat(descriptor, &mut status) } != 0 {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
            Examined::Gone
        } else {
            Examined::Failed
        };
    }
    // SAFETY: fcntl with F_GETFL takes an integer and returns the flags.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
        return Examined::Gone;
    }
    let writable = (flags >= 0).then_some(matches!(
        flags & libc::O_ACCMODE,
        libc::O_WRONLY | libc::O_RDWR
    ));
    let kind = match status.st_mode & libc::S_IFMT {
        libc::S_IFSOCK => ChannelKind::Socket,
        libc::S_IFIFO => ChannelKind::Pipe,
        libc::S_IFREG => ChannelKind::File,
        libc::S_IFDIR => ChannelKind::Directory,
        // SAFETY: isatty takes an integer.
        libc::S_IFCHR if unsafe { libc::isatty(descriptor) } == 1 => ChannelKind::Terminal,
        libc::S_IFCHR | libc::S_IFBLK => ChannelKind::Device,
        _ => ChannelKind::Other,
    };
    Examined::Open(crate::Channel {
        descriptor,
        kind,
        writable,
    })
}

/// The open descriptors at this moment, each judged by `fstat` and its open flags. The listing is
/// not complete when a name could not be read or a descriptor could not be examined.
pub(crate) fn open_channels() -> io::Result<crate::OpenChannels> {
    let mut complete = true;
    let mut numbers = Vec::new();
    for entry in std::fs::read_dir(descriptors())? {
        let number = entry
            .ok()
            .and_then(|entry| entry.file_name().to_str()?.parse::<i32>().ok());
        match number {
            Some(number) => numbers.push(number),
            None => complete = false,
        }
    }
    numbers.sort_unstable();
    let mut channels = Vec::new();
    for descriptor in numbers {
        match examine(descriptor) {
            Examined::Open(channel) => {
                complete &= channel.writable.is_some();
                channels.push(channel);
            }
            Examined::Gone => {}
            Examined::Failed => {
                complete = false;
                channels.push(crate::Channel {
                    descriptor,
                    kind: crate::ChannelKind::Unknown,
                    writable: None,
                });
            }
        }
    }
    let shared_mappings = super::shared_mappings().unwrap_or_else(|| {
        complete = false;
        Vec::new()
    });
    Ok(crate::OpenChannels {
        channels,
        shared_mappings,
        complete,
    })
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

/// Runs `work` on a new Unix thread with a guarded stack of at least `bytes` and wipes it
/// after joining. Lock, dump and fork protections depend on the allocation. The callback
/// runs only if the stack has every property in `required`.
pub(crate) fn run_on_stack<R: Send, F: FnOnce() -> R + Send>(
    bytes: usize,
    required: crate::StackProperties,
    work: F,
) -> Result<(R, crate::StackProperties), crate::StackError> {
    use crate::StackError;

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
        .checked_next_multiple_of(page_size())
        .ok_or(StackError::Size)?
        .max(libc::PTHREAD_STACK_MIN);
    let mut stack =
        Pages::stack(size).ok_or_else(|| StackError::System(io::ErrorKind::OutOfMemory.into()))?;
    let has = crate::StackProperties {
        locked: stack.is_locked(),
        out_of_dumps: stack.is_out_of_dumps(),
        out_of_children: stack.is_out_of_children(),
    };
    if !has.covers(required) {
        return Err(StackError::NotProtected(has));
    }
    let mut job = Job {
        work: Some(work),
        result: None,
    };
    // SAFETY: the attribute is initialized before use and destroyed once; the stack pages belong
    // to `stack`, which outlives the thread because the thread is joined before it is dropped.
    let (made, joined) = unsafe {
        let mut attributes: libc::pthread_attr_t = std::mem::zeroed();
        let mut thread: libc::pthread_t = std::mem::zeroed();
        let mut made = libc::pthread_attr_init(&mut attributes);
        let mut joined = 0;
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
                    joined = libc::pthread_join(thread, ptr::null_mut());
                }
            }
            libc::pthread_attr_destroy(&mut attributes);
        }
        (made, joined)
    };
    if joined != 0 {
        // The thread may still run on the stack and write to the job: neither may be given back.
        std::process::abort();
    }
    // The thread has ended: nothing else reaches the stack, whose frames may hold bytes that
    // were never written.
    stack.wipe_any();
    if made != 0 {
        return Err(StackError::System(io::Error::from_raw_os_error(made)));
    }
    match job.result {
        Some(Ok(value)) => Ok((value, has)),
        Some(Err(panic)) => std::panic::resume_unwind(panic),
        None => Err(StackError::System(io::Error::other(
            "the thread did not run the work",
        ))),
    }
}

/// The worker's standard input and output, unbuffered, so that no copy of a secret stays in a
/// buffer of the standard library. When dropped, both numbers are pointed at /dev/null, or at
/// an ended pipe where it could not be opened: the parent sees the end of the pipes at once,
/// however long the worker lives on.
pub(crate) struct WorkerStreams {
    input: ManuallyDrop<File>,
    output: ManuallyDrop<File>,
    /// /dev/null or an ended pipe, made before the isolation refuses opening for writing.
    nowhere: OwnedFd,
}

impl io::Read for WorkerStreams {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.input.read(buffer)
    }
}

impl io::Write for WorkerStreams {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.output.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

impl Drop for WorkerStreams {
    fn drop(&mut self) {
        for stream in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
            // SAFETY: dup2 and close take integers: the number now names what leads nowhere,
            // which closes the pipe it named and keeps the number taken, or the pipe is closed
            // outright. The files above never close them.
            unsafe {
                if libc::dup2(self.nowhere.as_raw_fd(), stream) == -1 {
                    libc::close(stream);
                }
            }
        }
    }
}

/// The read end of a pipe whose write end is closed: reading it gives the end, and nothing is
/// written to it. It stands in for /dev/null where that cannot be opened, so that the numbers of
/// the worker's streams stay taken and no later descriptor of the program gets them.
fn ended_pipe() -> Option<OwnedFd> {
    let mut ends = [0; 2];
    // SAFETY: pipe writes two new descriptors into the array it is given.
    if unsafe { libc::pipe(ends.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: both descriptors were just made and nothing else owns them.
    let [read, write] = ends.map(|end| unsafe { OwnedFd::from_raw_fd(end) });
    drop(write);
    Some(read)
}

/// The streams of a worker, which on Unix has no channel of another name.
pub(crate) fn worker_streams(channel: &str) -> io::Result<WorkerStreams> {
    if !channel.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // Without either the streams could not be ended while the process lives: no start.
    let nowhere = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .ok()
        .map(OwnedFd::from)
        .or_else(ended_pipe)
        .ok_or_else(|| io::Error::other("nothing to put in place of the streams"))?;
    // SAFETY: descriptors 0 and 1 are the pipes the parent made, open for the whole process;
    // `ManuallyDrop` never closes them.
    Ok(unsafe {
        WorkerStreams {
            input: ManuallyDrop::new(File::from_raw_fd(libc::STDIN_FILENO)),
            output: ManuallyDrop::new(File::from_raw_fd(libc::STDOUT_FILENO)),
            nowhere,
        }
    })
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
