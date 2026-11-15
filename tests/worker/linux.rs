//! Linux worker integration roles.
use super::*;

/// A failed call must have collected the child before the Worker is dropped.
pub(super) fn a_failed_call_ends_the_worker_before_it_is_dropped() {
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    let id = worker.call(b"pid", 16).unwrap();
    let path = format!("/proc/{}", std::str::from_utf8(id.as_bytes()).unwrap());
    assert!(std::path::Path::new(&path).exists());
    assert!(worker.call(b"huge", 10).is_err());
    assert!(
        !std::path::Path::new(&path).exists(),
        "worker was not collected"
    );
}

/// The `unsignalling` role: a program that isolated itself so that it signals only itself
/// cannot kill a worker it started before. Ending the worker still returns in time, and
/// says that the worker is left behind.
pub(super) fn unsignalling() {
    use secret_protection_core::Isolation;
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    let (gate, id) = exit_gate(&mut worker);
    let path = format!("/proc/{id}");
    let isolation = Isolation::enter_with(Options::new().signals_to_self_only());
    assert!(isolation.signals_to_self_only, "{isolation:?}");
    assert!(!worker.end(), "worker should still be running");
    drop(gate);
    within(Duration::from_secs(20), move || {
        while std::path::Path::new(&path).exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
    });
}

pub(super) fn role(name: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .env(ROLE, name)
        .output()
        .unwrap();
    super::support::role_ended(name, output.status, &output.stderr);
}

/// The answer of a filter that refuses a call with `error`.
const fn errno(error: i32) -> u32 {
    libc::SECCOMP_RET_ERRNO | error as u32
}

/// Installs a filter, which a started worker inherits, that gives `calls` the answers named
/// and allows every other call.
fn refuse(calls: &[(libc::c_long, u32)]) {
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    // Load the call's number, then answer or go on, call by call.
    let mut program = vec![instruction(0x20, 0, 0, 0)];
    for &(call, answer) in calls {
        program.push(instruction(0x15, 0, 1, call as u32));
        program.push(instruction(0x06, 0, 0, answer));
    }
    program.push(instruction(0x06, 0, 0, libc::SECCOMP_RET_ALLOW));
    install(&mut program);
}

/// Installs a filter, which a started worker inherits, that refuses every open for both
/// reading and writing, as a worker opens /dev/null, and allows every other call.
fn refuse_read_write_opens() {
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    // The flags are the third argument of openat; their two lowest bits say how it opens.
    install(&mut [
        instruction(0x20, 0, 0, 0),
        instruction(0x15, 0, 4, libc::SYS_openat as u32),
        instruction(0x20, 0, 0, 32),
        instruction(0x54, 0, 0, libc::O_ACCMODE as u32),
        instruction(0x15, 0, 1, libc::O_RDWR as u32),
        instruction(0x06, 0, 0, errno(libc::EACCES)),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]);
}

/// Installs `program` as a filter of this process and of what it starts.
fn install(program: &mut [libc::sock_filter]) {
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

/// The `unexamined` role: a sandbox refuses `fstat` on one descriptor. The list of descriptors
/// still reads, says it is not whole, and gives that one as unknown, never a kind it was not
/// seen to be; the others keep their kinds.
pub(super) fn unexamined() {
    use secret_protection_core::ChannelKind;
    use std::os::fd::AsRawFd;
    let hidden = std::fs::File::open("/dev/null").unwrap();
    let target = u32::try_from(hidden.as_raw_fd()).unwrap();
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let refused = libc::SECCOMP_RET_ERRNO | libc::EACCES as u32;
    // The call's number; for each way to `fstat`, the descriptor in its first argument.
    let mut program = vec![
        instruction(0x20, 0, 0, 0),
        instruction(0x15, 2, 0, libc::SYS_fstat as u32),
        instruction(0x15, 1, 0, libc::SYS_newfstatat as u32),
        instruction(0x15, 0, 3, libc::SYS_statx as u32),
        instruction(0x20, 0, 0, 16),
        instruction(0x15, 0, 1, target),
        instruction(0x06, 0, 0, refused),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ALLOW),
    ];
    install(&mut program);
    let open = secret_protection_core::open_channels().unwrap();
    assert!(!open.complete, "{open:?}");
    let kind = |descriptor: i32| {
        let channel = open
            .channels
            .iter()
            .find(|channel| channel.descriptor == descriptor);
        channel.map(|channel| (channel.kind, channel.writable))
    };
    assert_eq!(kind(hidden.as_raw_fd()), Some((ChannelKind::Unknown, None)));
    assert!(
        kind(2).is_some_and(|(kind, _)| kind != ChannelKind::Unknown),
        "{open:?}"
    );
}

/// The `unwaited` role: a program that ignores SIGCHLD, as many services do, has its ended
/// children taken off the system's list at once. Ending its worker still says that it ended.
pub(super) fn unwaited() {
    // SAFETY: sets the action of one signal to the system's own "ignore".
    let before = unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
    assert_ne!(before, libc::SIG_ERR);
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    assert_eq!(worker.call(b"public", 100).unwrap().as_bytes(), b"cilbup");
    assert!(worker.end(), "the worker was not seen to end");
}

/// Without a readable list of descriptors the worker cannot know what it holds: it says so,
/// and the parent ends it before any request. A list cut short is not complete for
/// `open_channels` either.
pub(super) fn without_listing() {
    refuse(&[(libc::SYS_getdents64, errno(libc::EACCES))]);
    match Worker::start(Options::new(), &[]) {
        Err(WorkerError::Unclean) => {}
        other => panic!("{other:?}"),
    }
    let open = secret_protection_core::open_channels().unwrap();
    assert!(!open.complete, "{open:?}");
}

/// Without a writable `/dev/null`, refusing an oversized request still closes the channel.
/// Later calls on the same worker return `BrokenPipe`.
pub(super) fn without_null() {
    refuse_read_write_opens();
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    assert_eq!(worker.call(b"linger", 10).unwrap().as_bytes(), b"lingers");
    assert!(worker.call(&vec![b'x'; MOST + 1], 10).is_err());
    assert_eq!(
        worker.call(b"public", 10).unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

/// A worker that cannot leave its parent's session says so and gets no request; on the
/// terminal it does not try to, and starts. One that dies before it reports is an error of
/// the start, at once: here the kernel kills it at the same call.
pub(super) fn without_setsid() {
    refuse(&[(libc::SYS_setsid, errno(libc::EPERM))]);
    let error = Worker::start(Options::new(), &[]).unwrap_err();
    assert!(matches!(error, WorkerError::Unclean), "{error:?}");
    assert_eq!(error.to_string(), "the worker's start was not clean");
    let mut on_terminal = Worker::start_on_terminal(Options::new(), &required()).unwrap();
    assert_eq!(
        on_terminal.call(b"public", 100).unwrap().as_bytes(),
        b"cilbup"
    );
    drop(on_terminal);
    // The killed worker would leave a core dump where the system writes them.
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads the struct, which lives for the call.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) }, 0);
    refuse(&[(libc::SYS_setsid, libc::SECCOMP_RET_KILL_PROCESS)]);
    let error = Worker::start(Options::new(), &[]).unwrap_err();
    let said = error.to_string();
    assert!(said.starts_with("the worker did not start"), "{said}");
    let WorkerError::Start(cause) = error else {
        panic!("{error:?}");
    };
    assert_eq!(cause.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// This child changes only the descriptor table of its own thread.
pub(super) fn separate_table() {
    use std::os::fd::AsRawFd;
    let worker = std::thread::spawn(|| {
        // SAFETY: unshare takes only flags and preserves the caller's existing descriptors.
        if unsafe { libc::unshare(libc::CLONE_FILES) } != 0 {
            return false;
        }
        let files: Vec<_> = (0..8)
            .map(|_| std::fs::File::open("/dev/null").unwrap())
            .collect();
        let report = secret_protection_core::open_channels().unwrap();
        assert!(report.complete);
        assert!(files.iter().all(|f| {
            report
                .channels
                .iter()
                .any(|c| c.descriptor == f.as_raw_fd())
        }));
        true
    });
    if !worker.join().unwrap() {
        support::skip_role("the host denied a separate descriptor table");
    }
}

fn kernel_secret(secret: &Secret) -> bool {
    let addr = secret.as_bytes().as_ptr() as usize;
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .any(|line| {
            let Some((range, _)) = line.split_once(' ') else {
                return false;
            };
            let Some((start, end)) = range.split_once('-') else {
                return false;
            };
            let start = usize::from_str_radix(start, 16).unwrap();
            let end = usize::from_str_radix(end, 16).unwrap();
            (start..end).contains(&addr) && line.ends_with("/secretmem (deleted)")
        })
}

pub(super) fn memory_baseline() {
    println!("{}", kernel_secret(&Secret::zeroed(8)));
}

pub(super) fn first_reply() {
    let baseline = std::process::Command::new(std::env::current_exe().unwrap())
        .env(ROLE, "memory-baseline")
        .output()
        .unwrap();
    assert!(baseline.status.success());
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    let reply = worker.call(b"public", 16).unwrap();
    assert_eq!(kernel_secret(&reply), baseline.stdout == b"true\n");
    assert!(worker.end());
    if baseline.stdout == b"false\n" {
        support::skip_role("kernel secret memory unavailable in the control process");
    }
}
