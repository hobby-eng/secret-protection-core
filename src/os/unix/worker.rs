//! The parent's side of a Unix worker: the launch by `posix_spawn` with private pipes, the
//! terminal for a worker on it, reads and writes with a deadline, and the end.
#![allow(
    unsafe_code,
    reason = "posix_spawn, fcntl, open, ttyname_r, poll, setsid and their structures are foreign"
)]

use std::ffi::{CStr, CString};
use std::io;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(coverage)]
use std::os::unix::ffi::OsStrExt;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::ptr;
use std::sync::mpsc;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use super::child;
use super::child::Child;

/// The parent's end of a worker: the worker's standard input and output, and the process.
pub(crate) struct WorkerProcess {
    pub(crate) to: Option<io::PipeWriter>,
    pub(crate) from: Option<io::PipeReader>,
    child: Child,
    exited: std::sync::Mutex<mpsc::Receiver<bool>>,
}

impl WorkerProcess {
    /// Spawns this program with piped input and output on Linux and macOS. It receives the
    /// worker setting and, in an instrumented build, the profile output path. A dedicated
    /// launcher thread uses an ordinary stack for spawn implementations that fork.
    /// With a deadline, nothing is launched once it has passed, and the wait for the launcher
    /// thread ends there too: a launch that has not returned by then fails with `TimedOut`, and the
    /// launcher ends its worker (see [`deliver`]).
    pub(crate) fn start(
        setting: &str,
        terminal: bool,
        deadline: Option<std::time::Instant>,
    ) -> io::Result<Self> {
        if cfg!(any(target_os = "android", target_os = "ios")) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(late());
        }
        // Linux starts the very file this process runs, even after its path came to name another;
        // other systems have only the path.
        #[cfg(target_os = "linux")]
        let program = c"/proc/self/exe".to_owned();
        #[cfg(not(target_os = "linux"))]
        let program = CString::new(std::os::unix::ffi::OsStringExt::into_vec(
            std::env::current_exe()?.into_os_string(),
        ))?;
        let terminal = if terminal { own_terminal()? } else { None };
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
        crate::os::linux::prepare_secret_pages();
        // No buffer: the child is handed over only to a start that still takes it.
        let (ready, started) = mpsc::sync_channel(0);
        let (done, exited) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("worker-wait".into())
            .spawn(move || {
                let tty = terminal.as_ref().map(AsRawFd::as_raw_fd);
                let child = spawn(&program, &variables, &streams, tty, false);
                drop((streams, terminal));
                deliver(child, &ready, &done);
            })?;
        let stopped = || io::Error::other("worker launcher stopped");
        let child = match deadline {
            None => started.recv().map_err(|_| stopped())??,
            Some(deadline) => started
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => late(),
                    mpsc::RecvTimeoutError::Disconnected => stopped(),
                })??,
        };
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

    /// Runs `work`, whose every read and write keeps the deadline by itself. The clock decides at
    /// the end too: an answer read past the deadline, which poll's steps of a millisecond let
    /// through, is late all the same.
    pub(crate) fn exchanging<T>(
        &mut self,
        deadline: Option<std::time::Instant>,
        work: impl FnOnce(&mut Self, Option<std::time::Instant>) -> io::Result<T>,
    ) -> io::Result<T> {
        let result = work(self, deadline)?;
        if deadline.is_some_and(|deadline| std::time::Instant::now() > deadline) {
            return Err(late());
        }
        Ok(result)
    }

    /// Reads all of `buffer` from the worker; with a `deadline`, fails with `TimedOut` once it
    /// passes instead of waiting on.
    pub(crate) fn read_exact_until(
        &mut self,
        buffer: &mut [u8],
        deadline: Option<std::time::Instant>,
    ) -> io::Result<()> {
        use std::io::Read;
        let from = self.from.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        let Some(deadline) = deadline else {
            return from.read_exact(buffer);
        };
        let mut filled = 0;
        while filled < buffer.len() {
            ready(from.as_raw_fd(), libc::POLLIN, deadline)?;
            match from.read(&mut buffer[filled..]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(read) => filled += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Writes all of `data` to the worker; with a `deadline`, as [`Self::read_exact_until`]. A
    /// pipe that polls writable takes PIPE_BUF bytes without waiting, so the data goes in such pieces.
    pub(crate) fn write_all_until(
        &mut self,
        data: &[u8],
        deadline: Option<std::time::Instant>,
    ) -> io::Result<()> {
        use std::io::Write;
        let to = self.to.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        let Some(deadline) = deadline else {
            return to.write_all(data);
        };
        for piece in data.chunks(libc::PIPE_BUF) {
            ready(to.as_raw_fd(), libc::POLLOUT, deadline)?;
            to.write_all(piece)?;
        }
        Ok(())
    }

    /// Closes the pipes and waits for exit. A stable kernel handle permits a termination
    /// request and a second bounded wait. The waiter still owns a child that survives.
    pub(crate) fn finish(&mut self) -> bool {
        self.close();
        let grace = crate::os::GRACE;
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

/// Waits until `descriptor` is ready for `events`, or its other end is closed, failing with
/// `TimedOut` once `deadline` passes.
fn ready(
    descriptor: libc::c_int,
    events: libc::c_short,
    deadline: std::time::Instant,
) -> io::Result<()> {
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the worker did not answer in time",
            ));
        }
        let millis =
            libc::c_int::try_from(left.as_millis().saturating_add(1)).unwrap_or(libc::c_int::MAX);
        let mut entry = libc::pollfd {
            fd: descriptor,
            events,
            revents: 0,
        };
        // SAFETY: polls one open descriptor through an entry that lives for the call.
        let polled = unsafe { libc::poll(&mut entry, 1, millis) };
        if polled > 0 {
            return Ok(());
        }
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

/// `name=value`, as the environment of a program holds it.
fn variable(name: &str, value: &[u8]) -> io::Result<CString> {
    Ok(CString::new([name.as_bytes(), b"=", value].concat())?)
}

/// Hands the launched child to the start waiting on `ready`, which takes it only while it still
/// waits; a start that gave up at its deadline no longer owns it, so it is ended here where a
/// stable handle allows, else when it finds its pipes closed. Then waits for it, for `done`.
fn deliver(
    child: io::Result<Child>,
    ready: &mpsc::SyncSender<io::Result<Child>>,
    done: &mpsc::SyncSender<bool>,
) {
    match child {
        Ok(child) => {
            if ready.send(Ok(child.clone())).is_err() {
                child.terminate();
            }
            let _ = done.send(child.wait());
        }
        Err(error) => {
            let _ = ready.send(Err(error));
        }
    }
}

/// The error of a deadline that passed.
fn late() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "the worker did not answer in time")
}

/// This program's terminal, opened anew by its name for reading and writing, as the standard error
/// of a worker on the terminal; not as a controlling terminal (`O_NOCTTY`). None when no standard
/// stream is a terminal.
fn own_terminal() -> io::Result<Option<OwnedFd>> {
    for stream in [libc::STDIN_FILENO, libc::STDERR_FILENO, libc::STDOUT_FILENO] {
        let mut name = [0 as libc::c_char; 128];
        // SAFETY: ttyname_r writes a NUL-terminated name of at most the buffer's length.
        if unsafe { libc::ttyname_r(stream, name.as_mut_ptr(), name.len()) } != 0 {
            continue;
        }
        // SAFETY: open reads the NUL-terminated name, which lives for the call.
        let opened = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if opened < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: open returned a new descriptor that nothing else owns.
        return above_streams(unsafe { OwnedFd::from_raw_fd(opened) }).map(Some);
    }
    Ok(None)
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
    terminal: Option<RawFd>,
    _private_table: bool,
) -> io::Result<Child> {
    let mut actions = MaybeUninit::uninit();
    // SAFETY: init sets up the actions in the space given, or fails and leaves it.
    check(unsafe { libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) })?;
    let mut actions = Actions(&mut actions);
    actions.dup2(streams[0].as_raw_fd(), libc::STDIN_FILENO)?;
    actions.dup2(streams[1].as_raw_fd(), libc::STDOUT_FILENO)?;
    // Standard error is the terminal for a worker on it, else /dev/null: never what the parent's
    // standard error happens to be, such as a socket to a log.
    match terminal {
        Some(terminal) => actions.dup2(terminal, libc::STDERR_FILENO)?,
        None => actions.open_null(libc::STDERR_FILENO)?,
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
fn spawn(
    _: &CStr,
    _: &[CString],
    _: &[OwnedFd; 2],
    _: Option<RawFd>,
    _: bool,
) -> io::Result<Child> {
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
pub(super) fn check(answer: libc::c_int) -> io::Result<()> {
    if answer == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(answer))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod launch_tests {
    use super::*;
    use std::fs::File;

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
                    spawn(c"/bin/true", &[], &streams, None, true)
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

    /// A child whose start gave up before the launch returned is ended where a stable handle
    /// allows, and collected; without one it ends when its input closes.
    #[test]
    fn an_abandoned_launch_is_ended_and_collected() -> io::Result<()> {
        let (input, writer) = io::pipe()?;
        let (reader, output) = io::pipe()?;
        let streams = [above_streams(input.into())?, above_streams(output.into())?];
        // cat waits on its input, which `writer` keeps open.
        let child = spawn(c"/bin/cat", &[], &streams, None, false);
        drop(streams);
        let stable = matches!(child, Ok(Child::Descriptor(_)));
        let mut writer = Some(writer);
        if !stable {
            writer = None;
        }
        let (ready, started) = mpsc::sync_channel(0);
        drop(started);
        let (done, exited) = mpsc::sync_channel(1);
        let launcher = std::thread::spawn(move || deliver(child, &ready, &done));
        let collected = exited.recv_timeout(std::time::Duration::from_secs(10));
        assert!(collected.is_ok(), "the abandoned child was not ended");
        launcher.join().unwrap();
        drop((writer, reader));
        Ok(())
    }
}
