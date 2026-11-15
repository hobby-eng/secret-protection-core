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
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::ptr::{self, NonNull};
use std::time::{Duration, Instant};

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
        Self::anonymous(bytes, Purpose::Secret).unwrap_or_else(|| super::out_of_memory(bytes))
    }

    /// The work area of a computation: anonymous pages as for a secret, never secret memory, or `None`
    /// when the system refuses them. They are locked only when RLIMIT_MEMLOCK holds all of them,
    /// which also commits them; a refused lock leaves them as they are.
    pub(crate) fn work_area(bytes: usize) -> Option<Self> {
        Self::anonymous(bytes, Purpose::Work)
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
        })
    }

    pub(crate) fn is_out_of_dumps(&self) -> bool {
        self.out_of_dumps
    }

    pub(crate) fn is_out_of_children(&self) -> bool {
        self.out_of_children
    }
}

/// What anonymous pages are for: a secret's are always locked and stay small pages; a work
/// area's are locked when the limit holds all of them.
#[derive(Clone, Copy)]
enum Purpose {
    Secret,
    Work,
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

/// Keeps a secret on small pages. Joining pages into a huge one copies them, and the kernel
/// frees the old ones without wiping them. A work area keeps the huge pages the system gives it:
/// a large computation is much slower without them. A kernel without huge pages refuses, which
/// leaves nothing to join.
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

/// The parent's end of a worker: the worker's standard input and output, and the process.
pub(crate) struct WorkerProcess {
    pub(crate) to: Option<ChildStdin>,
    pub(crate) from: Option<ChildStdout>,
    child: Child,
}

impl WorkerProcess {
    /// Starts this program again with the worker's variable alone in its environment, set to
    /// `setting`, and its standard input and output piped; without `terminal` its standard error
    /// goes nowhere. Android and iOS start no worker. The start runs on a thread of its own: an
    /// old C library starts a program with `fork`, whose child runs on a copy of the calling
    /// stack, and a protected one would be empty there.
    pub(crate) fn start(setting: &str, terminal: bool) -> io::Result<Self> {
        if cfg!(any(target_os = "android", target_os = "ios")) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let mut command = Command::new(std::env::current_exe()?);
        command
            .env_clear()
            .env(crate::worker::WORKER, setting)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(if terminal {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        let mut child = std::thread::Builder::new()
            .spawn(move || command.spawn())?
            .join()
            .map_err(|_| io::Error::other("the thread that starts the worker failed"))??;
        let (Some(to), Some(from)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        Ok(Self {
            to: Some(to),
            from: Some(from),
            child,
        })
    }

    /// Closes both pipes: a worker that waits to read ends, and so does one that waits to write.
    pub(crate) fn close(&mut self) {
        self.to = None;
        self.from = None;
    }

    /// Closes both pipes and waits for the worker; one still running after the grace time is killed
    /// and given as long again, so that this never waits for ever. Returns whether the worker
    /// ended. A program that may no longer signal other processes cannot kill it: the worker is
    /// then left behind.
    pub(crate) fn finish(&mut self) -> bool {
        self.close();
        let grace = super::GRACE;
        self.ends_within(grace) || (self.child.kill().is_ok() && self.ends_within(grace))
    }

    /// Takes a worker that has ended since off the system's list, without waiting.
    pub(crate) fn reap(&mut self) {
        let _ = self.child.try_wait();
    }

    /// Waits up to `limit` for the worker to end, and takes it off the system's list.
    fn ends_within(&mut self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(None) => return false,
                // The system has taken an ended child off its list itself, as with SIGCHLD ignored.
                Err(error) => return error.raw_os_error() == Some(libc::ECHILD),
            }
        }
    }
}

/// Where the system lists the open descriptors of the process.
const DESCRIPTORS: &std::ffi::CStr = if cfg!(target_vendor = "apple") {
    c"/dev/fd"
} else {
    c"/proc/self/fd"
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

/// Runs before `main` in every process that holds this crate. One started as a worker, with a
/// setting that `serve` takes, closes every descriptor above standard error here, where no code
/// of the program owns one yet: whatever its parent had open without close-on-exec. Rust's own
/// start has not run, so it calls the C library and code that needs nothing set up.
extern "C" fn shed_inherited() {
    // SAFETY: the name is NUL-terminated and the environment is set up before this runs; the
    // value, NUL-terminated as well, is read before anything can change it.
    let worker = unsafe {
        let value = libc::getenv(crate::worker::WORKER_NAME.as_ptr());
        !value.is_null() && crate::worker::is_setting(std::ffi::CStr::from_ptr(value))
    };
    if !worker {
        return;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: close_range takes integers (Linux 5.9); nothing owns these descriptors yet.
    if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } == 0 {
        return;
    }
    // SAFETY: the path is NUL-terminated; each entry is read while the listing is open; the
    // descriptors closed belong to no code yet, and the listing's own is left to closedir.
    unsafe {
        let listing = libc::opendir(DESCRIPTORS.as_ptr());
        if !listing.is_null() {
            let own = libc::dirfd(listing);
            loop {
                let entry = libc::readdir(listing);
                if entry.is_null() {
                    break;
                }
                let number = libc::atoi((*entry).d_name.as_ptr());
                if number > 2 && number != own {
                    libc::close(number);
                }
            }
            libc::closedir(listing);
        }
    }
}

/// Puts [`shed_inherited`] among the functions the system runs before `main`. On Apple systems
/// the section names its kind, pointers to such functions, so that every linker keeps it one.
#[used]
#[cfg_attr(
    any(target_os = "linux", target_os = "android"),
    unsafe(link_section = ".init_array")
)]
#[cfg_attr(
    target_vendor = "apple",
    unsafe(link_section = "__DATA,__mod_init_func,mod_init_funcs")
)]
static BEFORE_MAIN: extern "C" fn() = shed_inherited;

/// Whether the worker holds no descriptor but its standard streams, as the system lists them
/// when it comes to serve: what it inherited was closed before `main`, and what the program
/// opened since counts as well. A list that cannot be read proves nothing. Nothing is closed
/// here, where the program may own descriptors by now.
pub(crate) fn starts_clean() -> bool {
    // The listing's own descriptor takes the lowest free number, 3, and is gone with it.
    let alone = listed_descriptors().is_some_and(|open| open.iter().all(|&d| d <= 3));
    // SAFETY: fcntl with F_GETFD takes integers and only reads.
    alone && unsafe { libc::fcntl(3, libc::F_GETFD) } == -1
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
    Ok(crate::OpenChannels { channels, complete })
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
/// dumps and children, locked where the limit allows), wiped after the thread ends. The work runs
/// only when the stack has every property in `required`. glibc also puts the thread's own data and
/// static TLS at the top of a stack it is given.
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
    let mut stack = Pages::work_area(size)
        .ok_or_else(|| StackError::System(io::ErrorKind::OutOfMemory.into()))?;
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
/// buffer of the standard library. When dropped, both numbers are pointed at /dev/null, or
/// closed where it could not be opened: the parent sees the end of the pipes at once, however
/// long the worker lives on.
pub(crate) struct WorkerStreams {
    input: ManuallyDrop<File>,
    output: ManuallyDrop<File>,
    /// /dev/null, opened before the isolation refuses opening for writing.
    nowhere: Option<OwnedFd>,
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
        // SAFETY: dup2 and close take integers. Both numbers come to name /dev/null, which
        // closes the pipes they named, or are closed themselves. The files above never close
        // them.
        unsafe {
            match &self.nowhere {
                Some(nowhere) => {
                    libc::dup2(nowhere.as_raw_fd(), libc::STDIN_FILENO);
                    libc::dup2(nowhere.as_raw_fd(), libc::STDOUT_FILENO);
                }
                None => {
                    libc::close(libc::STDIN_FILENO);
                    libc::close(libc::STDOUT_FILENO);
                }
            }
        }
    }
}

/// The streams of a worker, which on Unix has no channel of another name.
pub(crate) fn worker_streams(channel: &str) -> io::Result<WorkerStreams> {
    if !channel.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let nowhere = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .ok()
        .map(OwnedFd::from);
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
