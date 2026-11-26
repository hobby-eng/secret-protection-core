//! The launcher waits for its own child. Only a kernel-held identity can receive a signal.
use std::io;
#[cfg(target_os = "linux")]
use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
};

#[derive(Clone)]
pub(super) enum Child {
    /// On systems with a pidfd, both waiting and signalling use the descriptor.
    #[cfg(target_os = "linux")]
    Descriptor(Arc<OwnedFd>),
    /// POSIX wait ownership belongs to this library. Never signal this number.
    #[cfg_attr(
        any(target_os = "android", target_os = "ios"),
        allow(dead_code, reason = "mobile systems never spawn workers")
    )]
    Number(libc::pid_t),
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(super) fn launch(
    program: &std::ffi::CStr,
    actions: &std::mem::MaybeUninit<libc::posix_spawn_file_actions_t>,
    attributes: &std::mem::MaybeUninit<libc::posix_spawnattr_t>,
    args: &[*const libc::c_char],
    env: &[*const libc::c_char],
    _shared_table: bool,
    deadline: Option<std::time::Instant>,
) -> io::Result<Child> {
    let late = || deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline);
    #[cfg(target_os = "linux")]
    if _shared_table {
        type PidfdSpawn = unsafe extern "C" fn(
            *mut libc::c_int,
            *const libc::c_char,
            *const libc::posix_spawn_file_actions_t,
            *const libc::posix_spawnattr_t,
            *const *mut libc::c_char,
            *const *mut libc::c_char,
        ) -> libc::c_int;
        // SAFETY: this is the optional glibc pidfd_spawn symbol, available since 2.39.
        let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"pidfd_spawn".as_ptr()) };
        // The lookup may wait on the loader's lock: the deadline is read after it.
        if late() {
            return Err(super::worker::late());
        }
        if !symbol.is_null() {
            // SAFETY: the named symbol has this ABI; all spawn inputs are initialized,
            // NUL-terminated where applicable, and remain live throughout the call.
            let start: PidfdSpawn = unsafe { std::mem::transmute(symbol) };
            let mut fd = -1;
            // SAFETY: the arrays end in null and the initialized actions outlive the call.
            let result = unsafe {
                start(
                    &mut fd,
                    program.as_ptr(),
                    actions.as_ptr(),
                    attributes.as_ptr(),
                    args.as_ptr().cast(),
                    env.as_ptr().cast(),
                )
            };
            if result == 0 {
                // SAFETY: on success pidfd_spawn transferred one open pidfd to the caller.
                return Ok(Child::Descriptor(Arc::new(unsafe {
                    OwnedFd::from_raw_fd(fd)
                })));
            }
            // Some kernels or container policies do not implement clone3. Ordinary spawning
            // can still support cooperative shutdown without a numeric termination request.
            if !matches!(
                result,
                libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL | libc::EPERM
            ) {
                return Err(io::Error::from_raw_os_error(result));
            }
        }
    }
    // The pidfd attempt took its time: the deadline is read again before the fallback.
    if late() {
        return Err(super::worker::late());
    }
    let mut pid = 0;
    // SAFETY: the strings and arrays are terminated, actions and attributes initialized.
    super::worker::check(unsafe {
        libc::posix_spawn(
            &mut pid,
            program.as_ptr(),
            actions.as_ptr(),
            attributes.as_ptr(),
            args.as_ptr().cast(),
            env.as_ptr().cast(),
        )
    })?;
    Ok(Child::Number(pid))
}

impl Child {
    /// Whether the worker was sent SIGKILL, or had already ended (ESRCH), which the wait that
    /// follows reports: only a stable handle can tell.
    pub(super) fn terminate(&self) -> bool {
        #[cfg(target_os = "linux")]
        if let Self::Descriptor(fd) = self {
            // SAFETY: the live fd is this worker's kernel identity, independent of PID reuse.
            let sent = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                )
            } == 0;
            return sent || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        }
        false
    }

    pub(super) fn wait(&self) -> bool {
        match self {
            #[cfg(target_os = "linux")]
            Self::Descriptor(fd) => {
                // Poll is independent of SIGCHLD disposition and works after external reaping.
                let mut watch = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                loop {
                    // SAFETY: the single entry is live, mutable, and holds the owned fd.
                    if unsafe { libc::poll(&raw mut watch, 1, -1) } > 0 {
                        if watch.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                            return false;
                        }
                        break;
                    }
                    if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                        return false;
                    }
                }
                loop {
                    let mut status = std::mem::MaybeUninit::uninit();
                    // SAFETY: waitid writes status and operates only on this open descriptor.
                    let result = unsafe {
                        libc::waitid(
                            libc::P_PIDFD,
                            fd.as_raw_fd() as libc::id_t,
                            status.as_mut_ptr(),
                            libc::WEXITED,
                        )
                    };
                    if result == 0 {
                        return true;
                    }
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return error.raw_os_error() == Some(libc::ECHILD);
                    }
                }
            }
            Self::Number(pid) => loop {
                // SAFETY: spawn supplied a positive child PID. This waiter is its one owner
                // in the POSIX fallback. No numeric PID is ever used to send a signal.
                if unsafe { libc::waitpid(*pid, std::ptr::null_mut(), 0) } == *pid {
                    return true;
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return error.raw_os_error() == Some(libc::ECHILD);
                }
            },
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    /// A worker collected before the kill is ended: ESRCH counts as such.
    #[test]
    fn a_child_collected_before_the_kill_counts_as_ended() {
        let mut process = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = libc::pid_t::try_from(process.id()).unwrap();
        // SAFETY: pidfd_open takes a number and flags and returns a new descriptor or -1.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(pidfd >= 0, "{}", io::Error::last_os_error());
        process.wait().unwrap();
        // SAFETY: the descriptor was just opened, and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(libc::c_int::try_from(pidfd).unwrap()) };
        assert!(Child::Descriptor(Arc::new(fd)).terminate());
    }

    /// The launch reads the deadline again after looking up pidfd_spawn, which may wait on the
    /// loader's lock, and before posix_spawn, the fallback: one already past starts nothing, with
    /// a descriptor table of its own or the parent's.
    #[test]
    fn no_launch_starts_past_its_deadline() {
        for shared_table in [false, true] {
            assert_eq!(
                launch_past_its_deadline(shared_table),
                Some(io::ErrorKind::TimedOut),
                "shared table {shared_table}"
            );
        }
    }

    /// What a launch of /bin/true whose deadline has passed fails with.
    fn launch_past_its_deadline(shared_table: bool) -> Option<io::ErrorKind> {
        let mut actions = std::mem::MaybeUninit::uninit();
        let mut attributes = std::mem::MaybeUninit::uninit();
        // SAFETY: each init sets up its value in the space given; both are destroyed below.
        unsafe {
            assert_eq!(libc::posix_spawn_file_actions_init(actions.as_mut_ptr()), 0);
            assert_eq!(libc::posix_spawnattr_init(attributes.as_mut_ptr()), 0);
        }
        let program = c"/bin/true";
        let arguments = [program.as_ptr(), std::ptr::null()];
        let environment = [std::ptr::null()];
        let past = Some(std::time::Instant::now());
        let refused = launch(
            program,
            &actions,
            &attributes,
            &arguments,
            &environment,
            shared_table,
            past,
        );
        // SAFETY: both were set up above and are used no more.
        unsafe {
            libc::posix_spawn_file_actions_destroy(actions.as_mut_ptr());
            libc::posix_spawnattr_destroy(attributes.as_mut_ptr());
        }
        refused.err().map(|error| error.kind())
    }
}
