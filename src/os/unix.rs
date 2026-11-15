//! Unix pages for secrets: anonymous mappings with `mlock`, between guard pages, kept out of core
//! dumps and child processes where the system allows. Also the core-dump limit, starting a worker
//! and the secret writer.
#![allow(
    unsafe_code,
    reason = "mmap, mprotect, mlock, getrlimit, setrlimit, madvise, minherit, munmap, sysconf and \
              write are foreign functions"
)]

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::ManuallyDrop;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::ptr::{self, NonNull};
use std::sync::mpsc;

use super::{Access, Pages, Region};

mod child;
pub(super) mod forks;
use child::Child;

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

/// What anonymous pages are for: a secret's are always locked and stay small pages; a work
/// area's are locked when the limit holds all of them.
#[derive(Clone, Copy)]
enum Purpose {
    Secret,
    Work,
}

impl Drop for Pages {
    fn drop(&mut self) {
        // Unmapping the pages also unlocks them. A child of `fork` leaves its parent's alone:
        // gone there, their addresses may hold what the child mapped since.
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

/// Asks the kernel to keep a secret on small pages. Joining pages into a huge one copies them,
/// and the kernel frees the old ones without wiping them. A work area keeps the huge pages the
/// system gives it: a large computation is much slower without them. A kernel without huge
/// pages refuses, which leaves nothing to join, so the answer is not read.
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
    pub(crate) to: Option<io::PipeWriter>,
    pub(crate) from: Option<io::PipeReader>,
    child: Child,
    exited: std::sync::Mutex<mpsc::Receiver<bool>>,
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
        let program = CString::new(std::env::current_exe()?.into_os_string().into_vec())?;
        #[cfg_attr(
            not(coverage),
            expect(unused_mut, reason = "one variable without coverage")
        )]
        let mut variables = vec![variable(crate::worker::WORKER, setting.as_bytes())?];
        // A measurement of coverage counts the worker as well: built for one, the worker gets the
        // name of the profile beside its setting, and no other variable of its parent's.
        #[cfg(coverage)]
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            variables.push(variable("LLVM_PROFILE_FILE", profile.as_bytes())?);
        }
        let (input, to) = io::pipe()?;
        let (from, output) = io::pipe()?;
        let streams = [above_streams(input.into())?, above_streams(output.into())?];
        // Reserve the waiter before creating a child. It remains responsible for reaping
        // even when the parent cannot terminate the worker or drops a failed startup.
        #[cfg(target_os = "linux")]
        super::linux::prepare_secret_pages();
        let (ready, started) = mpsc::sync_channel(1);
        let (done, exited) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("worker-wait".into())
            .spawn(move || {
                let child = spawn(&program, &variables, &streams, terminal, false);
                drop(streams);
                match child {
                    Ok(child) => {
                        let _ = ready.send(Ok(child.clone()));
                        let _ = done.send(child.wait());
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                    }
                }
            })?;
        let child = started
            .recv()
            .map_err(|_| io::Error::other("worker launcher stopped"))??;
        Ok(Self {
            to: Some(to),
            from: Some(from),
            child,
            exited: std::sync::Mutex::new(exited),
        })
    }

    /// Closes both pipes: a worker that waits to read ends, and so does one that waits to write.
    pub(crate) fn close(&mut self) {
        self.to = None;
        self.from = None;
    }

    /// Closes the pipes and waits for exit. A stable kernel handle permits a termination
    /// request and a second bounded wait. The waiter still owns a child that survives.
    pub(crate) fn finish(&mut self) -> bool {
        self.close();
        let grace = super::GRACE;
        let exited = self
            .exited
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match exited.recv_timeout(grace) {
            Ok(ended) => ended,
            Err(mpsc::RecvTimeoutError::Timeout) if self.child.terminate() => {
                exited.recv_timeout(grace) == Ok(true)
            }
            Err(_) => false,
        }
    }
}

/// `name=value`, as the environment of a program holds it.
fn variable(name: &str, value: &[u8]) -> io::Result<CString> {
    Ok(CString::new([name.as_bytes(), b"=", value].concat())?)
}

/// `end` at a number above standard error, so that moving one pipe to 0 or 1 in the worker cannot
/// overwrite the other first.
fn above_streams(end: OwnedFd) -> io::Result<OwnedFd> {
    if end.as_raw_fd() > 2 {
        return Ok(end);
    }
    // SAFETY: fcntl copies a descriptor this function owns to the lowest free number from 3, with
    // close-on-exec; the copy is new, and owned once, below.
    let copy = unsafe { libc::fcntl(end.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `copy` is a descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

/// Starts `program` with `variables` as its whole environment and `streams` as its standard input
/// and output, by `posix_spawn`, which runs no code of this program in the child. Every other
/// descriptor above standard error is closed there before the program runs, so that the start-up
/// code of its libraries finds none of the parent's: on Apple systems the system closes all that
/// no action names; on Linux a final close-from action closes the whole range.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn spawn(
    program: &CStr,
    variables: &[CString],
    streams: &[OwnedFd; 2],
    terminal: bool,
    _private_table: bool,
) -> io::Result<Child> {
    let mut actions = MaybeUninit::uninit();
    // SAFETY: init sets up the actions in the space given, or fails and leaves it.
    check(unsafe { libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) })?;
    let mut actions = Actions(&mut actions);
    actions.dup2(streams[0].as_raw_fd(), libc::STDIN_FILENO)?;
    actions.dup2(streams[1].as_raw_fd(), libc::STDOUT_FILENO)?;
    if !terminal {
        actions.open_null(libc::STDERR_FILENO)?;
    }
    // Where every descriptor no action names is closed, an action that names standard error
    // keeps it, as other systems keep one without close-on-exec.
    #[cfg(target_vendor = "apple")]
    if terminal && inheritable(libc::STDERR_FILENO) {
        actions.dup2(libc::STDERR_FILENO, libc::STDERR_FILENO)?;
    }
    #[cfg(not(target_vendor = "apple"))]
    if !_private_table && let Err(error) = actions.close_from(3) {
        #[cfg(target_os = "linux")]
        if error.kind() == io::ErrorKind::Unsupported {
            return std::thread::scope(|scope| {
                std::thread::Builder::new()
                    .spawn_scoped(scope, || {
                        private_close_on_exec()?;
                        spawn(program, variables, streams, terminal, true)
                    })?
                    .join()
                    .map_err(|_| io::Error::other("private worker launcher stopped"))?
            });
        }
        return Err(error);
    }
    let mut attributes = MaybeUninit::uninit();
    // SAFETY: init sets up the attributes in the space given, or fails and leaves it.
    check(unsafe { libc::posix_spawnattr_init(attributes.as_mut_ptr()) })?;
    let mut attributes = Attributes(&mut attributes);
    attributes.reset()?;
    let arguments = [program.as_ptr(), ptr::null()];
    let environment: Vec<*const libc::c_char> = variables
        .iter()
        .map(|variable| variable.as_ptr())
        .chain([ptr::null()])
        .collect();
    child::launch(
        program,
        actions.0,
        attributes.0,
        &arguments,
        &environment,
        !_private_table,
    )
}

/// Mark the temporary launcher's unshared descriptor table close-on-exec in one operation.
/// Its parent keeps ownership of all original descriptors. The launcher exits after spawn.
#[cfg(target_os = "linux")]
fn private_close_on_exec() -> io::Result<()> {
    // SAFETY: sigfillset initializes the set. Block user handlers until this temporary
    // thread exits, so none can open a fresh descriptor after close_range. Spawn
    // attributes independently reset the signal mask in the child.
    unsafe {
        let mut signals = MaybeUninit::uninit();
        if libc::sigfillset(signals.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        check(libc::pthread_sigmask(
            libc::SIG_BLOCK,
            signals.as_ptr(),
            ptr::null_mut(),
        ))?;
    }
    let flags = libc::CLOSE_RANGE_UNSHARE | libc::CLOSE_RANGE_CLOEXEC;
    // SAFETY: close_range takes descriptor numbers and flags. This operation marks the
    // calling thread's new table and leaves existing threads' flags and ownership intact.
    let result = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, flags) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Android and iOS start no worker.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn spawn(_: &CStr, _: &[CString], _: &[OwnedFd; 2], _: bool, _: bool) -> io::Result<Child> {
    Err(io::ErrorKind::Unsupported.into())
}

/// What the child of `posix_spawn` does with its descriptors before the program runs; destroyed
/// when dropped.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct Actions<'a>(&'a mut MaybeUninit<libc::posix_spawn_file_actions_t>);

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Actions<'_> {
    fn dup2(&mut self, from: i32, to: i32) -> io::Result<()> {
        // SAFETY: the actions are set up; the call adds one.
        check(unsafe { libc::posix_spawn_file_actions_adddup2(self.0.as_mut_ptr(), from, to) })
    }

    #[cfg(not(target_vendor = "apple"))]
    fn close_from(&mut self, first: libc::c_int) -> io::Result<()> {
        // Resolve at runtime: the GNU extension is available from glibc 2.34.
        // Older libraries can still load the crate and use non-worker operations.
        type CloseFrom =
            unsafe extern "C" fn(*mut libc::posix_spawn_file_actions_t, libc::c_int) -> libc::c_int;
        // SAFETY: dlsym takes a constant NUL-terminated name and the global symbol scope.
        let symbol = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"posix_spawn_file_actions_addclosefrom_np".as_ptr(),
            )
        };
        if symbol.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "worker requires a child-side close-from spawn action",
            ));
        }
        // SAFETY: the named function has the POSIX spawn-actions ABI above. The actions live
        // until spawn returns. The close-from runs after dup2 and before program initialization.
        let close_from: CloseFrom = unsafe { std::mem::transmute(symbol) };
        // SAFETY: self owns the initialized action list and first is a descriptor number.
        check(unsafe { close_from(self.0.as_mut_ptr(), first) })
    }

    /// Opens /dev/null for writing at `descriptor`.
    fn open_null(&mut self, descriptor: i32) -> io::Result<()> {
        let null = c"/dev/null".as_ptr();
        // SAFETY: the actions are set up, and the path is NUL-terminated; the call adds one.
        check(unsafe {
            libc::posix_spawn_file_actions_addopen(
                self.0.as_mut_ptr(),
                descriptor,
                null,
                libc::O_WRONLY,
                0,
            )
        })
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for Actions<'_> {
    fn drop(&mut self) {
        // SAFETY: the actions were set up, and are destroyed once, here.
        unsafe { libc::posix_spawn_file_actions_destroy(self.0.as_mut_ptr()) };
    }
}

/// The attributes of a start; destroyed when dropped.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct Attributes<'a>(&'a mut MaybeUninit<libc::posix_spawnattr_t>);

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Attributes<'_> {
    /// No signal blocked in the worker and SIGPIPE back at its default; on Apple systems also
    /// every descriptor that no action names closed.
    fn reset(&mut self) -> io::Result<()> {
        let mut signals = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: sigemptyset sets up the set in the space given, and sigaddset adds to it; the
        // attributes are set up, and each call copies the set.
        unsafe {
            libc::sigemptyset(signals.as_mut_ptr());
            check(libc::posix_spawnattr_setsigmask(
                self.0.as_mut_ptr(),
                signals.as_ptr(),
            ))?;
            libc::sigaddset(signals.as_mut_ptr(), libc::SIGPIPE);
            check(libc::posix_spawnattr_setsigdefault(
                self.0.as_mut_ptr(),
                signals.as_ptr(),
            ))?;
        }
        let flags = libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF;
        // An old glibc would make the child with `fork`, whose child runs the fork handlers and
        // reads the records of every thread; this flag makes it use `vfork`. A newer glibc
        // ignores it.
        #[cfg(target_os = "linux")]
        let flags = flags | libc::c_int::from(libc::POSIX_SPAWN_USEVFORK);
        #[cfg(target_vendor = "apple")]
        let flags = flags | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        // The flags are below 0x8000: they fit the short the call takes.
        let flags = flags as libc::c_short;
        // SAFETY: the attributes are set up; the call sets their flags.
        check(unsafe { libc::posix_spawnattr_setflags(self.0.as_mut_ptr(), flags) })
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for Attributes<'_> {
    fn drop(&mut self) {
        // SAFETY: the attributes were set up, and are destroyed once, here.
        unsafe { libc::posix_spawnattr_destroy(self.0.as_mut_ptr()) };
    }
}

/// The answer of a `posix_spawn` call, which is 0 or the number of the error.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn check(answer: libc::c_int) -> io::Result<()> {
    if answer == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(answer))
    }
}

/// Whether `descriptor` is open without close-on-exec, so that a started program gets it.
#[cfg(all(target_vendor = "apple", not(target_os = "ios")))]
fn inheritable(descriptor: i32) -> bool {
    // SAFETY: fcntl with F_GETFD takes integers and only reads.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    flags >= 0 && flags & libc::FD_CLOEXEC == 0
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

#[cfg(all(test, target_os = "linux"))]
mod launch_tests {
    use super::*;

    #[test]
    fn private_launcher_preserves_parent_descriptors_and_returns_no_private_fd() -> io::Result<()> {
        let file = File::open("/dev/null")?;
        // SAFETY: duplicate the test's file above the standard streams without close-on-exec.
        let number = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 3) };
        if number < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the preceding call returned a new descriptor owned by this test.
        let original = unsafe { OwnedFd::from_raw_fd(number) };
        let streams = [
            above_streams(File::open("/dev/null")?.into())?,
            above_streams(File::open("/dev/null")?.into())?,
        ];
        let child = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    private_close_on_exec()?;
                    // SAFETY: inspect the test-owned descriptor in this thread's private table.
                    let flags = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) };
                    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
                    spawn(c"/bin/true", &[], &streams, false, true)
                })
                .join()
                .map_err(|_| io::Error::other("private launcher failed"))
        })??;
        assert!(matches!(child, Child::Number(_)));
        assert!(!child.terminate());
        assert!(child.wait());
        // SAFETY: the original remains owned by the parent and was created without CLOEXEC.
        let flags = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC == 0);
        Ok(())
    }
}
