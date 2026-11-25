//! A process that already has another thread when it isolates itself: with
//! `Options::all_threads` the layer and the filter from Landlock ABI 8, and the filter alone on a
//! kernel without Landlock, reach that thread too; without it the thread keeps what isolation
//! takes from the caller.

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
    // The layer goes onto every thread from Landlock ABI 8 (Linux 7.0), and the filter only
    // where the layer did, or on a kernel without Landlock, where it waits for no layer.
    let abi = landlock_abi();
    let reaches = sync && !(1..8).contains(&abi);
    assert_eq!(
        (socket, file),
        (!reaches, !reaches),
        "Landlock ABI {abi}: {isolation:?}"
    );
    let process = if reaches {
        Reach::Process
    } else {
        Reach::Thread
    };
    assert_eq!(reach(Protection::NoNewSockets), Some(process));
    assert_eq!(reach(Protection::NoFileChanges), Some(process));
    assert_eq!(
        isolation.whole_process, reaches,
        "Landlock ABI {abi}: {isolation:?}"
    );
    // The namespaces need one thread whatever the option.
    assert!(!isolation.empty_network);
    drop(ask);
    sibling.join().unwrap();
}

/// The `foreign-sibling` role: a thread that holds a filter of its own makes the kernel refuse
/// the filter that allows everything, put onto every thread first, so the whole call stays on
/// the calling thread, the layer too, and says so.
pub(crate) fn foreign_sibling_role() {
    use secret_protection_core::{Options, Protection, Reach};
    use std::sync::mpsc;
    let (ready, filtered) = mpsc::channel::<()>();
    let (ask, asked) = mpsc::channel::<()>();
    let (answer, answers) = mpsc::channel::<bool>();
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
        while asked.recv().is_ok() {
            let path = std::env::temp_dir().join(format!("spc-foreign-{}", std::process::id()));
            let made = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .is_ok();
            let _ = fs::remove_file(&path);
            answer.send(made).unwrap();
        }
    });
    filtered.recv().unwrap();
    let isolation = Isolation::enter_with(Options::new().all_threads());
    // No layer went onto the other thread either: it still makes a new file.
    ask.send(()).unwrap();
    assert!(answers.recv().unwrap(), "{isolation:?}");
    let reach = (isolation.measures().into_iter())
        .find(|measure| measure.protection == Protection::NoNewSockets)
        .map(|measure| (measure.outcome, measure.reach));
    assert_eq!(
        reach.map(|(_, reach)| reach),
        Some(Reach::Thread),
        "{isolation:?}"
    );
    assert!(isolation.no_new_sockets && !isolation.whole_process);
    drop(ask);
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
    use secret_protection_core::{Options, Outcome, Protection, Reach};
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
        let calling = reach(&own) == Some((Outcome::Confirmed, Reach::Thread))
            && own.signals_to_self_only
            && !own.whole_process;
        let all = Isolation::enter_with(Options::new().signals_to_self_only().all_threads());
        let every =
            reach(&all) == Some((Outcome::Confirmed, Reach::Process)) && all.signals_to_self_only;
        // The parent's rule stays: the child cannot signal itself, its own rule notwithstanding.
        // SAFETY: kill with signal 0 only asks whether a signal could be sent.
        let refused = unsafe { libc::kill(libc::getpid(), 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES);
        drop(park);
        let _ = sibling.join();
        let code = i32::from(!calling) | i32::from(!every) << 1 | i32::from(!refused) << 2;
        // SAFETY: ends the child without running its parent's exit handlers.
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    // SAFETY: waits for the child made above, writing its status into a live slot.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status), "{status}");
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "1: the calling thread's filter was taken for every thread's; 2: TSYNC did not reach \
         them; 4: the child could signal itself"
    );
}
