//! The roles a child of the test plays on Linux: each isolates itself under a condition of
//! its own and ends well when the answer is as it should be.

use super::*;

/// Only the designated child's normal exit is evidence from the role.
fn child_code(child: libc::pid_t) -> i32 {
    assert!(child > 0);
    let mut status = 0;
    loop {
        // SAFETY: wait for one positive child PID and write into a live status slot.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        let error = io::Error::last_os_error();
        assert!(
            waited == -1 && error.kind() == io::ErrorKind::Interrupted,
            "waitpid: {error}"
        );
    }
    assert!(libc::WIFEXITED(status), "abnormal child status {status}");
    libc::WEXITSTATUS(status)
}

/// The `locked` role. A lock that took is still reported by a later call that does not ask
/// for it, and never by words about a call that was not made; a child made by `fork`, which
/// inherits no lock, does not report it.
pub(crate) fn locked_role() {
    use secret_protection_core::{Options, Outcome, Protection};
    let of = |isolation: Isolation| {
        isolation
            .measures()
            .into_iter()
            .find(|measure| measure.protection == Protection::MemoryLocked)
            .unwrap()
    };
    let isolation = Isolation::enter_with(Options::new().lock_all_memory());
    let buffer = vec![1_u8; 1 << 20];
    assert_eq!(
        buffer.iter().map(|&byte| usize::from(byte)).sum::<usize>(),
        1 << 20
    );
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let locked_kib: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmLck:"))
        .and_then(|value| value.trim().trim_end_matches(" kB").trim().parse().ok())
        .unwrap();
    let again = Isolation::enter();
    if isolation.memory_locked {
        assert!(locked_kib > 0, "{locked_kib}");
        assert!(again.memory_locked, "{again:?}");
        assert_eq!(of(again).evidence, "mlockall was accepted in this process");
        // SAFETY: the process has one thread, so the child may go on as any process.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", io::Error::last_os_error());
        if child == 0 {
            let inherited = Isolation::enter().memory_locked;
            // SAFETY: ends the child at once, without the parent's exit handlers.
            unsafe { libc::_exit(i32::from(inherited)) };
        }
        let status = child_code(child);
        assert_eq!(status, 0, "the child reported its parent's lock");
    } else {
        assert_eq!(of(isolation).outcome, Outcome::Refused);
        assert_eq!(of(isolation).evidence, "mlockall was refused");
        assert_eq!(of(again).outcome, Outcome::NotRequested);
        assert_eq!(of(again).evidence, "the call did not ask for it");
    }
}

/// The `forked` role: the signal rule names the process that asked for it. A child made by
/// `fork` inherits the rule with its parent's number: it must not report the protection until
/// it asks and gets a rule of its own, and a thread that did not ask never reports another
/// thread's.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn forked_role() {
    use secret_protection_core::{Options, Outcome, Protection};
    let options = Options::new().signals_to_self_only();
    let own = Isolation::enter_with(options);
    assert!(own.signals_to_self_only, "{own:?}");
    // SAFETY: the process has one thread, so the child may go on as any process.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork: {}", io::Error::last_os_error());
    if child == 0 {
        let silent = Isolation::enter().outcome(Protection::SignalsToSelfOnly);
        let asked = Isolation::enter_with(options).outcome(Protection::SignalsToSelfOnly);
        // SAFETY: signal 0 only asks whether a signal could be sent; getppid takes nothing.
        let reaches_parent = unsafe { libc::kill(libc::getppid(), 0) } == 0;
        let wrong = silent == Outcome::Confirmed || asked != Outcome::Confirmed || reaches_parent;
        // SAFETY: ends the child at once, without the parent's exit handlers.
        unsafe { libc::_exit(i32::from(wrong)) };
    }
    let status = child_code(child);
    assert_eq!(status, 0, "the child took its parent's rule for its own");
    // A second thread of a child gets a rule of the child's own. The first thread still holds
    // the parent's alone, and says nothing of the second thread's.
    // SAFETY: as above.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork: {}", io::Error::last_os_error());
    if child == 0 {
        let more = options.refuse_sendmsg();
        let other = std::thread::spawn(move || {
            Isolation::enter_with(more).outcome(Protection::SignalsToSelfOnly)
        });
        let others = other.join().unwrap_or(Outcome::Refused);
        let own = Isolation::enter().outcome(Protection::SignalsToSelfOnly);
        let wrong = others != Outcome::Confirmed || own == Outcome::Confirmed;
        // SAFETY: as above.
        unsafe { libc::_exit(i32::from(wrong)) };
    }
    let status = child_code(child);
    assert_eq!(status, 0, "a thread took another thread's rule for its own");
    // Nor after an update of the filter that failed: from here on no further filter goes in.
    install_a_filter_refusing_filters();
    // SAFETY: as above.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork: {}", io::Error::last_os_error());
    if child == 0 {
        let more = options.refuse_sendmsg();
        let asked = Isolation::enter_with(more).outcome(Protection::SignalsToSelfOnly);
        // SAFETY: as above.
        unsafe { libc::_exit(i32::from(asked == Outcome::Confirmed)) };
    }
    let status = child_code(child);
    assert_eq!(
        status, 0,
        "a refused filter left the parent's rule read as the child's"
    );
}

/// The `unmasked` role: the system refuses to block signals, so a handler could fork on the
/// thread that holds the gate of secret memory. No secret memory is taken then.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn unmasked_role() {
    install_a_filter_answering(libc::SYS_rt_sigprocmask, None, libc::EPERM);
    let secret = Secret::with_capacity(16);
    assert!(!is_secret_memory(&secret));
    assert!(secret.is_out_of_dumps() && secret.is_out_of_children());
}

/// The `policed` role: someone else's policy refuses just what the probes try, a socket, an
/// io_uring, a program and a file lock, and no filter of this crate's goes in. None of
/// these reads as confirmed, and a program that requires one stops.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn policed_role() {
    use secret_protection_core::{Options, Outcome, Protection};
    for call in [
        libc::SYS_socket,
        libc::SYS_io_uring_setup,
        libc::SYS_execve,
        libc::SYS_flock,
    ] {
        install_a_filter_answering(call, None, libc::EACCES);
    }
    install_a_filter_refusing_filters();
    let options = Options::new().refuse_file_locks();
    let isolation = Isolation::enter_with(options);
    for protection in [
        Protection::NoNewSockets,
        Protection::NoNewPrograms,
        Protection::FileLocksRefused,
    ] {
        assert_eq!(
            isolation.outcome(protection),
            Outcome::Unknown,
            "{protection}: {isolation:?}"
        );
    }
    let required = [Protection::NoNewSockets];
    let missing = Isolation::enter_requiring(options, &required).unwrap_err();
    assert_eq!(missing.missing, required);
}

/// The `undumpable-refused` role: someone else's policy refuses to clear the dumpable flag. The
/// isolation then enters no user namespace, in which every process of the user would hold the
/// right to read this one, and confirms neither the core-dump ban nor the empty network.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn undumpable_refused_role() {
    let before = fs::read_link("/proc/self/ns/user").unwrap();
    install_a_filter_answering(
        libc::SYS_prctl,
        Some(libc::PR_SET_DUMPABLE as u32),
        libc::EPERM,
    );
    let isolation = Isolation::enter();
    let after = fs::read_link("/proc/self/ns/user").unwrap();
    assert_eq!(after, before, "a user namespace was entered");
    assert!(
        !isolation.empty_network && !isolation.no_core_dumps,
        "{isolation:?}"
    );
}

/// The `own-pids` role: in a PID namespace of its own, as in a container, a tracer outside
/// it would read as none. The reading of memory is then unknown, not confirmed. Only a
/// child is in the new namespace. Where the limit allows a lock of all memory, a grandchild
/// in a further namespace has the child's number, 1, and must not take its lock for its own.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn own_pids_role() {
    use secret_protection_core::{Options, Outcome, Protection};
    // SAFETY: unshare takes flags only.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWPID) } != 0 {
        crate::support::skip_role(
            "this system allows no user namespace: the PID namespace is not checked",
        );
    }
    // SAFETY: the process has one thread, so the child may go on as any process.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork: {}", io::Error::last_os_error());
    if child == 0 {
        let reading = Isolation::enter().outcome(Protection::NoMemoryReading);
        if reading != Outcome::Unknown {
            std::process::exit(1);
        }
        let locked = Isolation::enter_with(Options::new().lock_all_memory()).memory_locked;
        // SAFETY: unshare takes flags only; the grandchild ends at once, and this child
        // waits for it and reads its status.
        unsafe {
            let code = if !locked {
                2
            } else if libc::unshare(libc::CLONE_NEWPID) != 0 {
                3
            } else {
                let grandchild = libc::fork();
                if grandchild == 0 {
                    libc::_exit(i32::from(Isolation::enter().memory_locked));
                }
                child_code(grandchild)
            };
            // Ends the child at once, without the parent's exit handlers.
            libc::_exit(code);
        }
    }
    assert!(child > 0, "{}", io::Error::last_os_error());
    let status = child_code(child);
    match status {
        2 => eprintln!(
            "{}mlockall was refused; nested lock ownership was not exercised",
            crate::support::NOT_CHECKED
        ),
        3 => eprintln!(
            "{}the second PID namespace was refused; nested lock ownership was not exercised",
            crate::support::NOT_CHECKED
        ),
        code => assert_eq!(code, 0, "namespace child failed"),
    }
}

/// The `relayered` role: the kernel refuses the Landlock layer once, here for want of a free
/// descriptor, and the filter goes in without it. The next call tries the layer again and
/// records it with one more filter; a third call adds nothing.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn relayered_role() {
    use secret_protection_core::{Outcome, Protection};
    if landlock_abi() < 6 {
        crate::support::skip_role(
            "this kernel's Landlock has no signal scope: the second try is not checked",
        );
    }
    let scope = Protection::SignalsWithinLayer;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct and setrlimit reads one; both live for the calls.
    // The three standard streams are open, so a limit of three leaves no descriptor free.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        let none_free = libc::rlimit {
            rlim_cur: 3,
            ..limit
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &none_free), 0);
    }
    let first = Isolation::enter();
    assert_eq!(first.outcome(scope), Outcome::Refused, "{first:?}");
    // SAFETY: as above.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let one_more = super::super::seccomp_filters().map(|filters| filters + 1);
    let second = Isolation::enter();
    assert_eq!(second.outcome(scope), Outcome::Confirmed, "{second:?}");
    assert_eq!(super::super::seccomp_filters(), one_more);
    assert_eq!(Isolation::enter(), second);
    assert_eq!(super::super::seccomp_filters(), one_more);
}

/// The `unlayered` role: the kernel knows Landlock, but refuses to apply the layer, as it
/// does beyond sixteen layers. The filter still goes in; the signal scope, which only the
/// layer brings, must read as refused, and writing files as refused by the filter.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn unlayered_role() {
    use secret_protection_core::{Outcome, Protection};
    install_a_filter_answering(libc::SYS_landlock_restrict_self, None, libc::EPERM);
    let isolation = Isolation::enter();
    assert!(
        isolation.no_file_changes && isolation.no_new_sockets,
        "{isolation:?}"
    );
    assert_eq!(
        isolation.outcome(Protection::SignalsWithinLayer),
        Outcome::Refused,
        "{isolation:?}"
    );
    assert_eq!(Isolation::enter(), isolation);
}

/// The `unlisted` role: the kernel refuses to list directories, so no thread can be looked at
/// for a tracer: the reading of memory is unknown, and a program that requires the protection
/// stops. The count of threads comes from `/proc/self/status`, which needs no listing, so the
/// process is still taken for the one thread it is.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn unlisted_role() {
    use secret_protection_core::{Options, Outcome, Protection};
    install_a_filter_answering(libc::SYS_getdents64, None, libc::EACCES);
    let isolation = Isolation::enter();
    assert_eq!(
        isolation.outcome(Protection::NoMemoryReading),
        Outcome::Unknown,
        "{isolation:?}"
    );
    assert!(isolation.whole_process, "{isolation:?}");
    let required = [Protection::NoCoreDumps, Protection::NoMemoryReading];
    let missing = Isolation::enter_requiring(Options::new(), &required).unwrap_err();
    assert_eq!(missing.missing, [Protection::NoMemoryReading]);
}

/// The speculation roles. In `speculating` the kernel refuses to turn speculation off; in
/// `unspeculated` it does not say how speculation stands, as AArch64 does for indirect
/// branches. A refusal reads as refused unless the processor needs no limit, what cannot be
/// read as unknown, and a program that requires the protection stops.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn speculation_role(readable: bool) {
    use secret_protection_core::{Options, Outcome, Protection};
    // PR_GET_SPECULATION_CTRL and PR_SET_SPECULATION_CTRL.
    let (get, set) = (52, 53);
    let limited = Protection::SpeculationLimited;
    let expected = if readable {
        install_a_filter_answering(libc::SYS_prctl, Some(set), libc::EPERM);
        let isolation = Isolation::enter();
        speculation_is_limited_as_reported(isolation);
        if isolation.speculation_limited {
            // Limited without a call, so a refused one changes nothing.
            eprintln!(
                "{}the processor needs no speculation limit, or it is on for good; a refused \
                 limit was not exercised",
                crate::support::NOT_CHECKED
            );
            Outcome::Confirmed
        } else {
            Outcome::Refused
        }
    } else {
        install_a_filter_answering(libc::SYS_prctl, Some(get), libc::ENODEV);
        Outcome::Unknown
    };
    let isolation = Isolation::enter();
    assert_eq!(isolation.outcome(limited), expected, "{isolation:?}");
    assert_eq!(
        Isolation::enter_requiring(Options::new(), &[limited]).is_ok(),
        expected == Outcome::Confirmed
    );
}

/// Installs a filter that answers `call` with `error`, whatever its first argument or only
/// for `first`, and allows every other call.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn install_a_filter_answering(call: libc::c_long, first: Option<u32>, error: i32) {
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let allow = instruction(0x06, 0, 0, libc::SECCOMP_RET_ALLOW);
    // Load the call's number; any other call is allowed.
    let mut program = vec![
        instruction(0x20, 0, 0, 0),
        instruction(0x15, 1, 0, call as u32),
        allow,
    ];
    if let Some(first) = first {
        // The low half of the first argument, which lies first on these machines.
        program.extend([
            instruction(0x20, 0, 0, 16),
            instruction(0x15, 1, 0, first),
            allow,
        ]);
    }
    program.push(instruction(
        0x06,
        0,
        0,
        libc::SECCOMP_RET_ERRNO | error as u32,
    ));
    let filter = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: prctl takes integers and, for the filter, a pointer to instructions that live
    // for the call; the kernel copies them.
    unsafe {
        assert_eq!(
            libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong
            ),
            0
        );
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &raw const filter,
                0 as libc::c_ulong,
                0 as libc::c_ulong
            ),
            0
        );
    }
}

/// The `traced` roles: once the test has attached to the first thread, enters the isolation,
/// from that thread or from a `sibling`, and says whether its memory is reported unreadable.
pub(crate) fn traced_role(sibling: bool) {
    let report = || {
        let mut byte = [0];
        io::stdin().read_exact(&mut byte).unwrap();
        let isolation = Isolation::enter();
        println!(
            "{}",
            if isolation.no_memory_reading {
                "unreadable"
            } else {
                "readable"
            }
        );
    };
    if sibling {
        std::thread::spawn(report).join().unwrap();
    } else {
        report();
    }
    super::super::idle();
}
