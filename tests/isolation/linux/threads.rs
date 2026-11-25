//! A process that already has another thread when it isolates itself: with
//! `Options::all_threads` the filter, and from Landlock ABI 8 the layer, reach that thread too;
//! without it the thread keeps what isolation takes from the caller.

use super::*;

/// The `all-threads` role, and the `one-thread-only` role without the option.
pub(crate) fn threads_role(sync: bool) {
    use secret_protection_core::{Options, Protection, Reach};
    use std::sync::mpsc;
    // The other thread waits for a question, and answers whether it could open a socket and a
    // new file for writing.
    let (ask, asked) = mpsc::channel::<()>();
    let (answer, answers) = mpsc::channel::<(bool, bool)>();
    let sibling = std::thread::spawn(move || {
        while asked.recv().is_ok() {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").is_ok();
            let path = std::env::temp_dir().join(format!("spc-threads-{}", std::process::id()));
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .is_ok();
            let _ = fs::remove_file(&path);
            answer.send((socket, file)).unwrap();
        }
    });
    let options = if sync {
        Options::new().all_threads()
    } else {
        Options::new()
    };
    let isolation = Isolation::enter_with(options);
    ask.send(()).unwrap();
    let (socket, file) = answers.recv().unwrap();
    let reach = |protection| {
        (isolation.measures().into_iter())
            .find(|measure| measure.protection == protection)
            .map(|measure| measure.reach)
    };
    // The filter goes onto every thread wherever seccomp has TSYNC (Linux 3.17); the layer from
    // Landlock ABI 8 (Linux 7.0), and a kernel without Landlock has only the filter to sync.
    let abi = landlock_abi();
    assert_eq!((socket, file), (!sync, !sync), "{isolation:?}");
    let process = if sync { Reach::Process } else { Reach::Thread };
    assert_eq!(reach(Protection::NoNewSockets), Some(process));
    assert_eq!(reach(Protection::NoFileChanges), Some(process));
    assert_eq!(
        isolation.whole_process,
        sync && !(1..8).contains(&abi),
        "Landlock ABI {abi}: {isolation:?}"
    );
    // The namespaces need one thread whatever the option.
    assert!(!isolation.empty_network);
    drop(ask);
    sibling.join().unwrap();
}

/// The `foreign-sibling` role: a thread that holds a filter of its own refuses TSYNC, so the
/// filter goes onto the calling thread alone and says so.
pub(crate) fn foreign_sibling_role() {
    use secret_protection_core::{Options, Protection, Reach};
    use std::sync::mpsc;
    let (ready, filtered) = mpsc::channel::<()>();
    let (done, finish) = mpsc::channel::<()>();
    let sibling = std::thread::spawn(move || {
        let allow = [libc::sock_filter {
            code: 0x06, // BPF_RET | BPF_K
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        }];
        let program = libc::sock_fprog {
            len: 1,
            filter: allow.as_ptr().cast_mut(),
        };
        // SAFETY: prctl takes integers, and the filter points to one instruction that lives for
        // the call.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &raw const program
                ),
                0
            );
        }
        ready.send(()).unwrap();
        let _ = finish.recv();
    });
    filtered.recv().unwrap();
    let isolation = Isolation::enter_with(Options::new().all_threads());
    let reach = (isolation.measures().into_iter())
        .find(|measure| measure.protection == Protection::NoNewSockets)
        .map(|measure| (measure.outcome, measure.reach));
    assert_eq!(
        reach.map(|(_, reach)| reach),
        Some(Reach::Thread),
        "{isolation:?}"
    );
    assert!(isolation.no_new_sockets && !isolation.whole_process);
    drop(done);
    sibling.join().unwrap();
}

/// The `repeated` role: calls with the option after the first add no filter, as each one stays
/// on every call of every thread, and keep the whole process.
pub(crate) fn repeated_role() {
    use secret_protection_core::Options;
    let (_park, parked) = std::sync::mpsc::channel::<()>();
    let sibling = std::thread::spawn(move || {
        let _ = parked.recv();
    });
    let first = Isolation::enter_with(Options::new().all_threads());
    let filters = seccomp_filters();
    for _ in 0..20 {
        let again = Isolation::enter_with(Options::new().all_threads());
        assert_eq!(again.whole_process, first.whole_process, "{again:?}");
    }
    assert_eq!(seccomp_filters(), filters);
    drop(_park);
    sibling.join().unwrap();
}

/// How many seccomp filters the calling thread holds.
fn seccomp_filters() -> Option<u32> {
    fs::read_to_string("/proc/thread-self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:"))?
        .trim()
        .parse()
        .ok()
}

/// The `forked-threads` role: a child of `fork` inherits its parent's filter, whose signal rule
/// names the parent. With a thread of its own started before, a filter it puts in again reaches
/// the calling thread alone, and with `all_threads` every thread.
pub(crate) fn forked_threads_role() {
    use secret_protection_core::{Options, Protection, Reach};
    let first = Isolation::enter_with(Options::new().signals_to_self_only());
    assert!(
        first.signals_to_self_only && first.whole_process,
        "{first:?}"
    );
    // SAFETY: fork in a process of one thread; the child runs only the checks below and leaves
    // by _exit.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let (park, parked) = std::sync::mpsc::channel::<()>();
        let sibling = std::thread::spawn(move || {
            let _ = parked.recv();
        });
        let reach = |isolation: &Isolation| {
            (isolation.measures().into_iter())
                .find(|measure| measure.protection == Protection::SignalsToSelfOnly)
                .map(|measure| (measure.outcome, measure.reach))
        };
        let own = Isolation::enter_with(Options::new().signals_to_self_only());
        let calling = reach(&own).map(|(_, reach)| reach) == Some(Reach::Thread)
            && own.signals_to_self_only
            && !own.whole_process;
        let all = Isolation::enter_with(Options::new().signals_to_self_only().all_threads());
        let every = reach(&all).map(|(_, reach)| reach) == Some(Reach::Process);
        drop(park);
        let _ = sibling.join();
        // SAFETY: ends the child without running its parent's exit handlers.
        unsafe { libc::_exit(i32::from(!calling) | i32::from(!every) << 1) };
    }
    let mut status = 0;
    // SAFETY: waits for the child made above, writing its status into a live slot.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status), "{status}");
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "1: the calling thread's filter was taken for every thread's; 2: TSYNC did not reach them"
    );
}
