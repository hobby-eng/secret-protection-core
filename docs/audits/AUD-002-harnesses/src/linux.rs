//! Linux security probes for AUD-002.
#![allow(
    unsafe_code,
    reason = "the probes exercise pidfds, signal syscalls and a foreign seccomp filter"
)]

use std::error::Error;
use std::io;
use std::process::{Child, Command};

use secret_protection_core::{Isolation, Options};

struct Target(Child);

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(crate) fn ipc() -> Result<(), Box<dyn Error>> {
    let before = std::fs::read_link("/proc/self/ns/ipc")?;
    let isolation = Isolation::enter();
    if !isolation.empty_network {
        println!("SKIP: this system refused a network namespace");
        return Ok(());
    }
    let after = std::fs::read_link("/proc/self/ns/ipc")?;
    if before == after {
        println!("FAIL: empty_network is true but the IPC namespace is shared: {after:?}");
        return Err(io::Error::other("the IPC namespace was not isolated").into());
    }
    println!("PASS: network and IPC namespaces differ from their parent");
    Ok(())
}

pub(crate) fn pidfd_signal() -> Result<(), Box<dyn Error>> {
    let mut target = Target(Command::new("sleep").arg("30").spawn()?);
    // SAFETY: pidfd_open reads no memory and returns a new descriptor for the synthetic child.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, target.0.id(), 0_u32) };
    let pidfd = i32::try_from(pidfd)?;
    if pidfd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: getpid reads no memory.
    let own = unsafe { libc::getpid() };
    // SAFETY: dup2 makes the target pidfd numerically equal to this process's PID; both descriptors
    // stay open and are closed below.
    let duplicate = unsafe { libc::dup2(pidfd, own) };
    if duplicate < 0 {
        // SAFETY: closes the descriptor returned by pidfd_open.
        unsafe { libc::close(pidfd) };
        return Err(io::Error::last_os_error().into());
    }
    let outcome = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                refuse_landlock()?;
                let isolation = Isolation::enter_with(Options::new().signals_to_self_only());
                if !isolation.foreign_signals_refused {
                    return Err(io::Error::other("the signal option did not read back"));
                }
                // SAFETY: signal 0 changes no process state; a null siginfo and zero flags are valid.
                let sent =
                    unsafe { libc::syscall(libc::SYS_pidfd_send_signal, duplicate, 0, 0, 0) };
                if sent == 0 {
                    println!(
                        "FAIL: pidfd_send_signal reached a foreign process through the filter"
                    );
                    return Err(io::Error::other("a foreign signal was allowed").into());
                }
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EACCES) {
                    return Err(error.into());
                }
                println!("PASS: pidfd_send_signal was refused with EACCES");
                Ok(())
            })
            .join()
    });
    // SAFETY: closes the two descriptors opened above; the worker thread has finished.
    unsafe {
        libc::close(duplicate);
        if duplicate != pidfd {
            libc::close(pidfd);
        }
    }
    target.0.kill()?;
    target.0.wait()?;
    outcome.map_err(|_| io::Error::other("the probe thread panicked"))??;
    Ok(())
}

pub(crate) fn answer(request: &[u8]) -> Option<Vec<u8>> {
    use std::os::fd::RawFd;

    let number = request.strip_prefix(b"inherited:")?;
    let descriptor = std::str::from_utf8(number).ok()?.parse::<RawFd>().ok()?;
    // SAFETY: fcntl and write use the inherited descriptor number supplied by the parent and a
    // one-byte synthetic buffer; no memory of another process is accessed.
    let open = unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0;
    if open {
        // SAFETY: the one-byte buffer lives for the call.
        unsafe { libc::write(descriptor, b"x".as_ptr().cast(), 1) };
    }
    Some(if open {
        b"open".to_vec()
    } else {
        b"closed".to_vec()
    })
}

pub(crate) fn inherited_fd() -> Result<(), Box<dyn Error>> {
    use secret_protection_core::Worker;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    if std::path::Path::new("/proc/self/fd").exists() {
        return Err(io::Error::other("this probe must run without procfs").into());
    }
    let (mut parent, inherited) = UnixStream::pair()?;
    // SAFETY: clears close-on-exec on one synthetic socket, deliberately making it inheritable.
    if unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_SETFD, 0) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    refuse_calls(&[libc::SYS_close_range])?;
    let mut worker = Worker::start(Options::new(), &[])?;
    let request = format!("inherited:{}", inherited.as_raw_fd());
    let answer = worker.call(request.as_bytes(), 16)?;
    if answer.as_bytes() == b"open" {
        let mut byte = [0];
        parent.read_exact(&mut byte)?;
        println!("FAIL: the worker kept an inherited socket and wrote {byte:?} through it");
        return Err(io::Error::other("an inherited channel remained usable").into());
    }
    if answer.as_bytes() != b"closed" {
        return Err(io::Error::other("the inherited socket check failed in the worker").into());
    }
    println!("PASS: the worker inherited no socket");
    Ok(())
}

fn refuse_landlock() -> io::Result<()> {
    refuse_calls(&[
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
    ])
}

fn refuse_calls(calls: &[libc::c_long]) -> io::Result<()> {
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let mut program = vec![instruction(0x20, 0, 0, 0)];
    for &number in calls {
        program.extend([
            instruction(0x15, 0, 1, number as u32),
            instruction(0x06, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
        ]);
    }
    program.push(instruction(0x06, 0, 0, libc::SECCOMP_RET_ALLOW));
    let filter = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: prctl reads no memory for NO_NEW_PRIVS and copies the filter, whose instructions live
    // for the call. This foreign filter makes the probe exercise the seccomp-only path of old Linux.
    let installed = unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &raw const filter,
                0,
                0,
            ) == 0
    };
    if installed {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
