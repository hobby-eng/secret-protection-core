//! AUD-005 probe of signal ownership after a failed filter upgrade in a forked child.
#![allow(
    unsafe_code,
    reason = "the probe uses fork, signal 0 and a foreign seccomp filter"
)]
#![allow(
    clippy::print_stderr,
    reason = "an audit command reports the observed state to its captured stderr"
)]

use std::error::Error;
use std::io;

use secret_protection_core::{Isolation, Options, Outcome, Protection};

fn refuse_filter_upgrades() -> io::Result<()> {
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let mut program = [
        instruction(0x20, 0, 0, 0),
        instruction(0x15, 0, 3, libc::SYS_prctl as u32),
        instruction(0x20, 0, 0, 16),
        instruction(0x15, 0, 1, libc::PR_SET_SECCOMP as u32),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ALLOW),
    ];
    let filter = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: prctl reads the scalar arguments and copies the filter, whose instructions live for
    // the call. The process already has no_new_privs from its first isolation.
    let installed = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &raw const filter,
            0,
            0,
        )
    } == 0;
    if installed {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let first = Isolation::enter_with(Options::new().signals_to_self_only());
    if first.outcome(Protection::SignalsToSelfOnly) != Outcome::Confirmed {
        return Err(io::Error::other("the initial signal rule was not confirmed").into());
    }
    refuse_filter_upgrades()?;
    // SAFETY: this process is single-threaded. The child only calls async-signal-safe operations
    // until Isolation::enter_with, whose fork behavior is the subject of this probe.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if child == 0 {
        let isolation =
            Isolation::enter_with(Options::new().signals_to_self_only().refuse_sendmsg());
        let outcome = isolation.outcome(Protection::SignalsToSelfOnly);
        // SAFETY: signal 0 changes no process state; getpid and getppid only read identifiers.
        let (to_self, to_parent) = unsafe {
            (
                libc::kill(libc::getpid(), 0),
                libc::kill(libc::getppid(), 0),
            )
        };
        eprintln!("child outcome={outcome:?}, kill(self)={to_self}, kill(parent)={to_parent}");
        std::process::exit(i32::from(outcome != Outcome::Refused));
    }
    let mut status = 0;
    // SAFETY: waits for the child just made and writes its status.
    if unsafe { libc::waitpid(child, &mut status, 0) } != child {
        return Err(io::Error::last_os_error().into());
    }
    if status != 0 {
        eprintln!("FAIL: a failed filter upgrade confirmed the parent's signal rule in the child");
        return Err(io::Error::other("the child reported the wrong signal owner").into());
    }
    eprintln!("PASS: the child did not confirm its parent's signal rule");
    Ok(())
}
