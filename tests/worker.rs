// long: one program of roles, each a worker the parent starts again, read best whole.
//! Exercises worker admission, request limits, transport failure and shutdown. The parent
//! and worker use the same executable. The outcomes depend on the platform and on whether
//! the launcher acquired a stable handle for termination.
#![allow(
    unsafe_code,
    reason = "the checks look at descriptors and sessions with the system's calls"
)]
#![allow(
    clippy::print_stdout,
    reason = "a test program with a main of its own reports each check, as a test harness does"
)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test program with a main of its own, which clippy does not see as a test: a failed \
              check panics, as in a test harness"
)]

#[path = "support/run.rs"]
mod support;
use support::run;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use secret_protection_core::{
    Keystroke, Options, Protection, Secret, SecretLine, Worker, WorkerError, serve,
};

/// The longest request the worker takes.
const MOST: usize = 1 << 20;
/// An answer far beyond what a pipe holds (64 KiB on Linux).
const HUGE: usize = 4 << 20;
/// The variable that gives a child of the test its part.
const ROLE: &str = "SECRET_PROTECTION_CORE_TEST_ROLE";
/// The variable that names, to the `kept` role, the descriptor its parent left it.
#[cfg(unix)]
const KEPT: &str = "SECRET_PROTECTION_CORE_TEST_KEPT";

/// Set in a worker that was asked to stay after its pipes close.
static LINGERS: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
static EXIT_GATE: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();
/// How long such a worker stays, at most: long past every wait of its parent, so that within a
/// check it ends only when it is killed.
const LINGER_SECONDS: u32 = 30;
/// Inodes of up to 16 FIFOs found at descriptors 3 through 255 before `main`. Two words retain
/// the full inode even when the target has no 64-bit atomics.
#[cfg(unix)]
static PIPES_BEFORE_MAIN: [[std::sync::atomic::AtomicU32; 2]; 16] =
    [const { [const { std::sync::atomic::AtomicU32::new(0) }; 2] }; 16];

/// Fills [`PIPES_BEFORE_MAIN`], before `main`, with calls that need nothing set up.
#[cfg(unix)]
extern "C" fn record_pipes_before_main() {
    let mut found = 0;
    for descriptor in 3..256 {
        // SAFETY: an all-zero `stat` is valid, and fstat writes it for the descriptor or fails.
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let open = unsafe { libc::fstat(descriptor, &mut status) } == 0;
        let pipe = open && status.st_mode & libc::S_IFMT == libc::S_IFIFO;
        if let Some([low, high]) = PIPES_BEFORE_MAIN.get(found).filter(|_| pipe) {
            #[allow(clippy::useless_conversion, reason = "ino_t can be u32 or u64")]
            let inode = u64::from(status.st_ino);
            low.store(inode as u32, Ordering::Relaxed);
            high.store((inode >> 32) as u32, Ordering::Relaxed);
            found += 1;
        }
    }
}

/// Puts [`record_pipes_before_main`] among the functions the system runs before `main`.
#[cfg(unix)]
#[used]
#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
#[cfg_attr(
    target_vendor = "apple",
    unsafe(link_section = "__DATA,__mod_init_func,mod_init_funcs")
)]
static RECORD_PIPES_BEFORE_MAIN: extern "C" fn() = record_pipes_before_main;

/// AddressSanitizer asks the program for its options. Its leak check needs ptrace, which an
/// isolated process refuses, and a worker gets no environment to turn it off in.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn __asan_default_options() -> *const std::ffi::c_char {
    c"detect_leaks=0".as_ptr()
}

/// The worker's answers, by request.
fn answer(request: &[u8]) -> Secret {
    let text = match request {
        #[cfg(windows)]
        b"test token metadata" => windows::token_metadata(),
        b"environment" => std::env::vars_os()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(","),
        #[cfg(unix)]
        b"descriptors" => descriptors(),
        #[cfg(unix)]
        b"stderr" => identity(libc::STDERR_FILENO),
        #[cfg(unix)]
        b"pipes before main" => PIPES_BEFORE_MAIN
            .iter()
            .map(|[low, high]| {
                u64::from(low.load(Ordering::Relaxed))
                    | (u64::from(high.load(Ordering::Relaxed)) << 32)
            })
            .take_while(|&inode| inode != 0)
            .map(|inode| inode.to_string())
            .collect::<Vec<_>>()
            .join(","),
        #[cfg(unix)]
        // SAFETY: getsid and getpid take integers and touch no memory.
        b"session" => (unsafe { libc::getsid(0) == libc::getpid() }).to_string(),
        b"pid" => std::process::id().to_string(),
        b"large" => "x".repeat(100),
        b"huge" => "x".repeat(HUGE),
        #[cfg(unix)]
        bytes if bytes.starts_with(b"wait for ") => {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::OsStr::from_bytes(&bytes[9..]);
            let file = std::fs::File::open(path).unwrap();
            assert!(EXIT_GATE.set(file).is_ok());
            std::process::id().to_string()
        }
        b"linger" => {
            LINGERS.store(true, Ordering::Relaxed);
            "lingers".to_owned()
        }
        b"slow" => {
            std::thread::sleep(Duration::from_secs(3));
            "slow".to_owned()
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        b"type" => {
            let key = b'x';
            // SAFETY: TIOCSTI reads the one byte given, which lives for the call.
            let typed = unsafe { libc::ioctl(libc::STDERR_FILENO, unix::TIOCSTI, &raw const key) };
            if typed == 0 {
                "typed".to_owned()
            } else {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(0)
                    .to_string()
            }
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        b"hidden" => {
            let mut line = SecretLine::with_capacity(64);
            match secret_protection_core::read_hidden_line("Password: ", &mut line) {
                Ok(secret_protection_core::LineEnd::Entered) => format!("line:{}", line.as_str()),
                Ok(end) => format!("{end:?}"),
                Err(error) => format!("error:{:?}", error.kind()),
            }
        }
        // A second call of `serve` in a worker: it returns at once and serves nothing.
        b"again" => serve(MOST, answer).to_string(),
        [1, ..] | [2] | [3] => {
            // A password typed in a window, one keystroke per request, would be collected in a
            // `SecretLine` kept by the worker; here each request stands alone.
            let mut line = SecretLine::with_capacity(8);
            line.apply(Keystroke::from_bytes(request).unwrap()).unwrap();
            line.characters().to_string()
        }
        other => other.iter().rev().map(|&byte| char::from(byte)).collect(),
    };
    let mut secret = Secret::with_capacity(text.len());
    secret.push(text.as_bytes()).unwrap();
    secret
}

/// The worker's open descriptors, as /proc/self/fd or /dev/fd lists them, its listing excepted.
#[cfg(unix)]
fn descriptors() -> String {
    let listed = if cfg!(target_vendor = "apple") {
        "/dev/fd"
    } else {
        "/proc/self/fd"
    };
    let mut numbers: Vec<i32> = std::fs::read_dir(listed)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    numbers.sort_unstable();
    // The highest is the listing's own descriptor.
    numbers.pop();
    numbers
        .iter()
        .map(|&number| {
            // Where a descriptor above the standard streams leads, where the system says.
            match std::fs::read_link(format!("/proc/self/fd/{number}")) {
                Ok(target) if number > 2 => format!("{number}={}", target.display()),
                _ => number.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The device and inode of what `descriptor` leads to, or "closed".
#[cfg(unix)]
fn identity(descriptor: i32) -> String {
    // SAFETY: an all-zero `stat` is valid, and fstat writes it for the descriptor or fails.
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::fstat(descriptor, &mut status) } != 0 {
        return "closed".to_owned();
    }
    format!("{}:{}", status.st_dev, status.st_ino)
}

/// What a worker has open while it serves: its standard streams, and /dev/null, which takes
/// the place of its pipes once it serves no more.
#[cfg(unix)]
fn its_own() -> &'static [u8] {
    if cfg!(target_os = "linux") {
        b"0,1,2,3=/dev/null"
    } else {
        b"0,1,2,3"
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the table of every check and role of the program, read best whole"
)]
fn main() {
    // The `late` role opens a file of its own before it comes to `serve`.
    #[cfg(unix)]
    let early = (std::env::var(ROLE).as_deref() == Ok("late"))
        .then(|| std::fs::File::open("/dev/null").unwrap());
    #[cfg(target_os = "linux")]
    let _sibling =
        (std::env::var("SECRET_PROTECTION_CORE_WORKER").as_deref() == Ok("12,0")).then(|| {
            // The fixture reserves the two Windows-only flags for a pre-main sibling on
            // Linux. The real launcher controls the environment and all descriptors.
            let (ready, receiver) = std::sync::mpsc::sync_channel(0);
            let sibling = std::thread::spawn(move || {
                ready.send(()).unwrap();
                std::thread::park();
            });
            receiver.recv().unwrap();
            sibling
        });
    if serve(MOST, answer) {
        // `serve` closed nothing: the file the program opened first is still its own.
        #[cfg(unix)]
        if let Some(file) = early {
            std::process::exit(i32::from(file.metadata().is_err()));
        }
        // A worker that was asked to linger does not end when its pipes close, as long as the
        // numbers of its streams are still taken.
        #[cfg(unix)]
        // SAFETY: fcntl with F_GETFD takes integers and only reads.
        let taken =
            unsafe { libc::fcntl(0, libc::F_GETFD) != -1 && libc::fcntl(1, libc::F_GETFD) != -1 };
        #[cfg(not(unix))]
        let taken = true;
        #[cfg(unix)]
        if let Some(mut gate) = EXIT_GATE.get() {
            use std::io::Read;
            // EOF is the parent's release. A dead test parent also closes its writer.
            assert_eq!(gate.read(&mut [0]).unwrap(), 0);
        }
        if taken && LINGERS.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(LINGER_SECONDS.into()));
        }
        return;
    }
    match std::env::var(ROLE).as_deref() {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little"
        ))]
        Ok("without-listing") => return linux::without_listing(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little"
        ))]
        Ok("unwaited") => return linux::unwaited(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little"
        ))]
        Ok("separate-table") => return linux::separate_table(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little"
        ))]
        Ok("first-reply") => return linux::first_reply(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little"
        ))]
        Ok("memory-baseline") => return linux::memory_baseline(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little"
        ))]
        Ok("unexamined") => return linux::unexamined(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little"
        ))]
        Ok("without-setsid") => return linux::without_setsid(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little"
        ))]
        Ok("unsignalling") => return linux::unsignalling(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little"
        ))]
        Ok("without-null") => return linux::without_null(),
        Ok("unserved") => return unserved(),
        #[cfg(unix)]
        Ok("kept") => return unix::kept(),
        #[cfg(unix)]
        Ok("streamless") => return unix::streamless(),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Ok("on-a-terminal") => return unix::on_a_terminal(),
        _ => {}
    }
    if !cfg!(any(target_os = "linux", target_os = "macos", windows)) {
        run(
            "every start answers Unsupported where no worker starts",
            || {
                let unsupported = |started: Result<Worker, WorkerError>| {
                    assert!(matches!(
                        started,
                        Err(WorkerError::Start(error)) if error.kind() == std::io::ErrorKind::Unsupported
                    ));
                };
                unsupported(Worker::start(Options::new(), &[]));
                unsupported(Worker::start_within(Options::new(), &[], Duration::ZERO));
                unsupported(Worker::start_on_terminal(Options::new(), &[]));
            },
        );
        support::finish();
        return;
    }
    #[cfg(target_os = "linux")]
    run(
        "a worker started while Yama lets any process of the user attach reports its memory open",
        || {
            use secret_protection_core::Outcome;
            let worker = Worker::start(Options::new(), &[Protection::WholeProcess]).unwrap();
            let expected = if !support::attaching_restricted() {
                Outcome::Refused
            } else if support::initial_pid_namespace() {
                Outcome::Confirmed
            } else {
                Outcome::Unknown
            };
            assert_eq!(
                worker.isolation().outcome(Protection::NoMemoryReading),
                expected
            );
        },
    );
    #[cfg(target_os = "linux")]
    run(
        "a worker with another thread at its start is refused before a request",
        || {
            // That thread could hold a descriptor table of its own, which no census reads.
            let options = Options::new().refuse_dynamic_code().microsoft_signed_only();
            let refused = Worker::start(options, &[]).unwrap_err();
            assert!(matches!(refused, WorkerError::Unclean), "{refused}");
        },
    );
    run(
        "a worker answers what it is asked, isolated",
        a_worker_answers_isolated,
    );
    run(
        "a worker gets nothing of its parent's but its pipes",
        a_worker_gets_nothing_but_its_pipes,
    );
    #[cfg(target_os = "linux")]
    run(
        "a worker applies the options it is given",
        a_worker_applies_its_options,
    );
    run(
        "a worker that lacks a required protection is stopped before any request",
        a_worker_lacking_a_protection_is_stopped,
    );
    run(
        "a refused answer ends the worker at once, however long the answer",
        a_refused_answer_ends_the_worker,
    );
    run(
        "a request beyond the worker's limit ends it",
        a_request_beyond_the_limit_ends_the_worker,
    );
    run(
        "a lingering worker is terminated only with a stable process handle",
        a_worker_that_lingers_is_killed,
    );
    run(
        "a call past its deadline fails at once and gives the worker up",
        a_call_past_its_deadline_gives_up,
    );
    run(
        "a program that reaches the start of a worker before serve starts none",
        a_worker_starts_no_worker,
    );
    #[cfg(unix)]
    run(
        "a program that comes to serve with a file of its own keeps it and is not clean",
        unix::a_late_serve_closes_nothing,
    );
    #[cfg(unix)]
    run(
        "a program whose worker variable holds no setting keeps what it inherited",
        unix::a_program_without_a_setting_keeps_what_it_inherited,
    );
    #[cfg(unix)]
    run(
        "a worker's start-up code finds no descriptor of its parent's",
        unix::a_worker_inherits_nothing_its_libraries_could_find,
    );
    #[cfg(windows)]
    run(
        "another process that opens the worker's pipe first does not stop the start",
        a_stray_client_does_not_stop_the_start,
    );
    #[cfg(unix)]
    run(
        "a worker starts from a protected stack",
        a_worker_starts_from_a_protected_stack,
    );
    #[cfg(unix)]
    run(
        "a program whose standard streams are closed starts both kinds of worker",
        unix::a_program_without_streams_starts_workers,
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    run(
        "a worker on a terminal reads and writes it but cannot type into it",
        unix::a_worker_on_a_terminal_cannot_type_into_it,
    );
    #[cfg(target_os = "linux")]
    run(
        "a worker's channel cannot be opened again through /proc",
        unix::a_workers_channel_cannot_be_opened_again,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little"
    ))]
    {
        run(
            "a worker that cannot list what it inherited is refused",
            || linux::role("without-listing"),
        );
        run(
            "the first worker reply preserves Linux secret memory eligibility",
            || linux::role("first-reply"),
        );
        run(
            "channel enumeration follows the calling thread descriptor table",
            || linux::role("separate-table"),
        );
        run(
            "a program that ignores SIGCHLD still ends its worker",
            || linux::role("unwaited"),
        );
        run(
            "channels that cannot be looked at are listed as unknown, in a list not whole",
            || linux::role("unexamined"),
        );
        run(
            "a worker that cannot leave the session, or dies before it reports, is refused",
            || linux::role("without-setsid"),
        );
        run(
            "a program that may not signal others leaves a stubborn worker behind, in time",
            || linux::role("unsignalling"),
        );
        run(
            "without /dev/null a worker that serves no more still ends its streams",
            || linux::role("without-null"),
        );
    }
    support::finish();
}

/// What every worker must have on the systems where it starts.
fn required() -> Vec<Protection> {
    let mut required = vec![Protection::WholeProcess];
    #[cfg(target_os = "linux")]
    if support::initial_pid_namespace() && support::attaching_restricted() {
        required.push(Protection::NoMemoryReading);
    }
    #[cfg(not(target_os = "linux"))]
    required.push(Protection::NoMemoryReading);
    if cfg!(unix) {
        required.push(Protection::NoCoreDumps);
    }
    if cfg!(target_os = "macos") || support::LINUX_SECCOMP {
        required.extend([Protection::NoNewSockets, Protection::NoFileChanges]);
    }
    if cfg!(windows) || support::LINUX_SECCOMP {
        required.push(Protection::NoNewPrograms);
    }
    if cfg!(windows) || speculation_can_be_limited() {
        required.push(Protection::SpeculationLimited);
    }
    if cfg!(windows) {
        required.extend([
            Protection::NoNewSockets,
            Protection::NoPlantedLibraries,
            Protection::DesktopRestricted,
            Protection::LowIntegrity,
        ]);
    }
    required
}

/// Whether this kernel limits both kinds of speculation for a program that asks, or has no need
/// to, by its own answer before anything is changed. Linux on AArch64 gives a program no control
/// of indirect branches, and a virtual machine may be given none of either kind.
fn speculation_can_be_limited() -> bool {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        /// PR_GET_SPECULATION_CTRL, and the bits "the program may change it" and "off".
        const GET: libc::c_int = 52;
        const CHANGEABLE_OR_OFF: libc::c_int = 0b101;
        [0, 1].into_iter().all(|kind: libc::c_ulong| {
            // SAFETY: prctl takes integers and touches no memory of this process.
            let state = unsafe {
                libc::prctl(
                    GET,
                    kind,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            state == 0 || (state > 0 && state & CHANGEABLE_OR_OFF != 0)
        })
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    false
}

fn a_worker_answers_isolated() {
    let result = Worker::start(Options::new(), &required());
    #[cfg(windows)]
    if let Err(ref error) = result {
        let mut observer = Worker::start(Options::new(), &[]).unwrap();
        let diagnostic = observer.call(b"test token metadata", 4096).unwrap();
        panic!(
            "strict startup failed: {error:?}; fresh AppContainer measurement: {:?}",
            diagnostic.as_str()
        );
    }
    let mut worker = result.unwrap();
    assert!(worker.isolation().whole_process, "{worker:?}");
    assert_eq!(worker.call(b"public", 100).unwrap().as_bytes(), b"cilbup");
    // Its debug text shows what holds, and nothing it was sent.
    let shown = format!("{worker:?}");
    assert!(
        shown.starts_with("Worker { isolation:") && !shown.contains("public"),
        "{shown}"
    );
    // Keystrokes, as a window sends them.
    let key = Keystroke::Char('ж').to_bytes();
    assert_eq!(worker.call(key.as_bytes(), 10).unwrap().as_bytes(), b"1");
    assert_eq!(worker.call(b"", 10).unwrap().as_bytes(), b"");
    // A worker serves once.
    assert_eq!(worker.call(b"again", 10).unwrap().as_bytes(), b"false");
    // An answer as long as allowed passes.
    assert_eq!(worker.call(b"large", 100).unwrap().as_bytes().len(), 100);
    // A request longer than the worker's first buffer of 4 KiB gets a larger one.
    let long: Vec<u8> = (b'a'..=b'z').cycle().take(5000).collect();
    let reversed: Vec<u8> = long.iter().rev().copied().collect();
    assert_eq!(worker.call(&long, 5000).unwrap().as_bytes(), reversed);
}

fn a_worker_gets_nothing_but_its_pipes() {
    // A descriptor opened without close-on-exec, which a started program would inherit.
    #[cfg(unix)]
    // SAFETY: dup takes an integer and returns a new descriptor, closed below.
    let leaked = unsafe { libc::dup(0) };
    let mut worker = Worker::start(Options::new(), &required()).unwrap();
    let environment = worker.call(b"environment", 1000).unwrap();
    let names = environment.as_str().unwrap();
    // Windows starts no process in an AppContainer without a few variables of its own, and
    // points those of the user's folders at the container's.
    let systems: &[&str] = if cfg!(windows) {
        &["SystemRoot", "LOCALAPPDATA", "TEMP", "TMP"]
    } else {
        &[]
    };
    // A measurement of coverage gives the worker the name of its profile, which the profiling
    // runtime may echo in a variable of its own.
    let measured = |name: &str| cfg!(coverage) && name.contains("LLVM_PROFILE");
    assert!(
        names
            .split(',')
            .all(|name| name == "SECRET_PROTECTION_CORE_WORKER"
                || systems.contains(&name)
                || measured(name)),
        "{names}"
    );
    assert!(names.contains("SECRET_PROTECTION_CORE_WORKER"), "{names}");
    #[cfg(unix)]
    {
        assert_eq!(
            worker.call(b"descriptors", 100).unwrap().as_bytes(),
            its_own()
        );
        assert_eq!(worker.call(b"session", 10).unwrap().as_bytes(), b"true");
        // Its standard error goes to /dev/null; a worker on the terminal gets the terminal.
        let null = std::fs::File::open("/dev/null").unwrap();
        let stderr = worker.call(b"stderr", 100).unwrap();
        let null = std::os::fd::AsRawFd::as_raw_fd(&null);
        assert_eq!(stderr.as_str().unwrap(), identity(null));
        // SAFETY: closes the descriptor opened above, once.
        unsafe { libc::close(leaked) };
        // A worker on the terminal leaves the session as well, so that it cannot type into the
        // shell; its standard error is the terminal, opened anew, or /dev/null without one.
        let mut on_terminal = Worker::start_on_terminal(Options::new(), &required()).unwrap();
        assert_eq!(
            on_terminal.call(b"session", 10).unwrap().as_bytes(),
            b"true"
        );
        // SAFETY: isatty takes an integer and only asks.
        let terminal = [0, 2, 1]
            .into_iter()
            .find(|&stream| unsafe { libc::isatty(stream) } == 1);
        let stderr = on_terminal.call(b"stderr", 100).unwrap();
        assert_eq!(stderr.as_str().unwrap(), identity(terminal.unwrap_or(null)));
    }
}

/// The options of the filter, which only Linux and Android have; Android starts no worker.
#[cfg(target_os = "linux")]
fn a_worker_applies_its_options() {
    let options = Options::new().refuse_file_locks().refuse_sendmsg();
    let required = [Protection::FileLocksRefused, Protection::SendmsgRefused];
    let worker = Worker::start(options, &required);
    if support::LINUX_SECCOMP {
        let worker = worker.unwrap();
        assert!(worker.isolation().file_locks_refused && worker.isolation().sendmsg_refused);
    } else {
        let WorkerError::Missing(missing) = worker.unwrap_err() else {
            panic!("worker did not report its missing seccomp options");
        };
        assert_eq!(missing.missing, required);
    }
    // Without the options neither holds, and the worker says they were not asked for.
    let plain = Worker::start(Options::new(), &[]).unwrap();
    assert!(!plain.isolation().file_locks_refused && !plain.isolation().sendmsg_refused);
    assert_eq!(
        plain.isolation().outcome(Protection::SendmsgRefused),
        secret_protection_core::Outcome::NotRequested
    );
}

fn a_worker_lacking_a_protection_is_stopped() {
    // A protection no worker has here: Linux and macOS load any DLL, Windows writes files where a
    // low label allows it.
    let impossible = if cfg!(windows) {
        Protection::NoFileChanges
    } else {
        Protection::MicrosoftSignedOnly
    };
    let error = Worker::start(Options::new(), &[Protection::WholeProcess, impossible]).unwrap_err();
    let said = error.to_string();
    assert!(
        said.starts_with("the worker is not isolated enough"),
        "{said}"
    );
    let WorkerError::Missing(missing) = error else {
        panic!("{error:?}");
    };
    assert_eq!(missing.missing, [impossible]);
    assert!(missing.isolation.whole_process);
}

/// Runs `end` on a thread of its own and fails when it takes longer than `limit`: a worker that
/// waits for its parent, which waits for it, would hang the test for ever.
fn within(limit: Duration, end: impl FnOnce() + Send + 'static) {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        end();
        let _ = done.send(());
    });
    finished
        .recv_timeout(limit)
        .unwrap_or_else(|_| panic!("not done within {limit:?}"));
}

fn a_refused_answer_ends_the_worker() {
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    // The worker is left writing an answer that no pipe holds whole.
    let refused = worker
        .call(b"huge", HUGE - 1)
        .map(|_| ())
        .map_err(|error| error.kind());
    assert_eq!(refused, Err(std::io::ErrorKind::InvalidData));
    // The worker was given up: every later call is refused.
    let refused = worker
        .call(b"public", 100)
        .map(|_| ())
        .map_err(|error| error.kind());
    assert_eq!(refused, Err(std::io::ErrorKind::BrokenPipe));
    assert!(worker.end(), "failed exchange left the worker running");
    // The same from a drop alone, with the answer never read.
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    assert!(worker.call(b"huge", 10).is_err());
    within(Duration::from_secs(20), move || drop(worker));
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little"
    ))]
    linux::a_failed_call_ends_the_worker_before_it_is_dropped();
}

fn a_request_beyond_the_limit_ends_the_worker() {
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    // The worker reads the length, takes nothing more and ends: the call fails.
    assert!(worker.call(&vec![b'x'; MOST + 1], 10).is_err());
    assert!(worker.call(b"public", 100).is_err());
    within(Duration::from_secs(20), move || drop(worker));
    // A worker that lives on after it stopped serving does not keep its parent waiting: its
    // streams ended with `serve`, so the request it left unread fails at once.
    within(Duration::from_secs(20), || {
        let mut worker = Worker::start(Options::new(), &[]).unwrap();
        assert_eq!(worker.call(b"linger", 10).unwrap().as_bytes(), b"lingers");
        assert!(worker.call(&vec![b'x'; MOST + 1], 10).is_err());
        assert_eq!(
            worker.call(b"public", 10).unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    });
}

/// A program whose `main` reached `Worker::start` before `serve` would start itself without
/// end, each copy waiting for the next. In a process started as a worker the start is refused.
fn a_worker_starts_no_worker() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .env(ROLE, "unserved")
        // No setting that `serve` takes: the program goes on as one that did not call it.
        .env("SECRET_PROTECTION_CORE_WORKER", "none")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A process of the same user may open the worker's pipe before the worker does, as a program
/// that looks at every pipe would. It is put off, and the worker starts all the same. Here a
/// thread of the test takes the pipe as soon as it is listed, a few times.
#[cfg(windows)]
fn a_stray_client_does_not_stop_the_start() {
    use std::sync::atomic::AtomicUsize;
    let done = std::sync::Arc::new(AtomicBool::new(false));
    let taken = std::sync::Arc::new(AtomicUsize::new(0));
    let (stop, count) = (std::sync::Arc::clone(&done), std::sync::Arc::clone(&taken));
    let stray = std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            // A listing that fails ends this pass; the next one lists again.
            for entry in std::fs::read_dir(r"\\.\pipe\")
                .unwrap()
                .map_while(Result::ok)
            {
                let ours = entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("secret-protection-core.");
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                if ours && let Ok(pipe) = std::fs::File::open(entry.path()) {
                    // Only the pipe of a worker of this process counts, and is held; one of
                    // another program is let go at once.
                    if served_here(&pipe) {
                        count.fetch_add(1, Ordering::Relaxed);
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    drop(pipe);
                }
            }
        }
    });
    // The thread is listing pipes by the time a worker's appears. Every start succeeds; one in
    // which the thread came first is enough, and several are tried for it.
    std::thread::sleep(Duration::from_millis(200));
    for _ in 0..8 {
        let mut worker = Worker::start(Options::new(), &required()).unwrap();
        assert_eq!(worker.call(b"public", 100).unwrap().as_bytes(), b"cilbup");
        if taken.load(Ordering::Relaxed) > 0 {
            break;
        }
    }
    done.store(true, Ordering::Relaxed);
    stray.join().unwrap();
    assert!(
        taken.load(Ordering::Relaxed) > 0,
        "the test never took a pipe"
    );
}

/// Whether this process holds the server end of `pipe`: its own worker's.
#[cfg(windows)]
fn served_here(pipe: &std::fs::File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    let mut server = 0;
    // SAFETY: the handle is the open pipe, and the call writes one number.
    let read = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server) } != 0;
    read && server == std::process::id()
}

/// The `unserved` role: the worker's variable is set, and the program is past `serve`.
fn unserved() {
    match Worker::start(Options::new(), &[]) {
        Err(WorkerError::Start(error)) => assert_eq!(error.kind(), std::io::ErrorKind::Other),
        other => panic!("{other:?}"),
    }
}

/// A call past its deadline ends the worker; it does not wait for the late answer.
fn a_call_past_its_deadline_gives_up() {
    // A start past its deadline fails, at whatever step it was.
    match Worker::start_within(Options::new(), &[], Duration::ZERO) {
        Err(WorkerError::Start(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        }
        other => panic!("{other:?}"),
    }
    let mut worker = Worker::start_within(Options::new(), &[], Duration::from_secs(60)).unwrap();
    let answer = worker
        .call_within(b"abc", 10, Duration::from_secs(60))
        .unwrap();
    assert_eq!(answer.as_bytes(), b"cba");
    let asked = std::time::Instant::now();
    let late = worker
        .call_within(b"slow", 10, Duration::from_millis(300))
        .unwrap_err();
    assert_eq!(late.kind(), std::io::ErrorKind::TimedOut);
    // The deadline, and the bounded wait for the worker to end.
    assert!(
        asked.elapsed() < Duration::from_millis(2900),
        "{:?}",
        asked.elapsed()
    );
    let after = worker.call(b"abc", 10).unwrap_err();
    assert_eq!(after.kind(), std::io::ErrorKind::BrokenPipe);
}

/// A lingering worker can be terminated through a stable process handle. On platforms
/// without one, the parent stops waiting and reports that the worker is still running.
fn a_worker_that_lingers_is_killed() {
    within(Duration::from_secs(20), || {
        let mut worker = Worker::start(Options::new(), &[]).unwrap();
        #[cfg(unix)]
        let (_gate, _id) = exit_gate(&mut worker);
        #[cfg(not(unix))]
        assert_eq!(worker.call(b"linger", 10).unwrap().as_bytes(), b"lingers");
        #[cfg(target_os = "linux")]
        let can_force = linux_pidfd(&_id);
        #[cfg(not(target_os = "linux"))]
        let can_force = cfg!(windows);
        assert_eq!(worker.end(), can_force);
        #[cfg(target_os = "macos")]
        {
            let pid = _id.parse().unwrap();
            assert_eq!(observed_child(pid), ChildState::Running);
            drop(_gate);
            while observed_child(pid) != ChildState::Collected {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    });
}

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
enum ChildState {
    Running,
    Exited,
    Collected,
}

/// WNOWAIT leaves collection to the library's waiter. An exited child still waiting
/// to be collected returns success here. ECHILD marks the end of our parent relationship.
#[cfg(target_os = "macos")]
fn observed_child(pid: libc::id_t) -> ChildState {
    loop {
        // SAFETY: zero represents a siginfo buffer without an event, including si_pid 0.
        let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: the PID belongs to the launched worker and the status buffer is writable.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                &raw mut status,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            if status.si_pid == 0 {
                return ChildState::Running;
            }
            assert_eq!(status.si_pid as libc::id_t, pid);
            return ChildState::Exited;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            assert_eq!(error.raw_os_error(), Some(libc::ECHILD), "{error}");
            return ChildState::Collected;
        }
    }
}

#[cfg(unix)]
fn exit_gate(worker: &mut Worker) -> (std::fs::File, String) {
    use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
    let path = std::env::temp_dir().join(format!("spc-exit-gate-{}", std::process::id()));
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the NUL-terminated path is valid; mkfifo refuses an existing entry.
    let made = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
    assert_eq!(made, 0, "mkfifo: {}", std::io::Error::last_os_error());
    let bootstrap = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .unwrap();
    let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let request = [b"wait for ".as_slice(), path.as_os_str().as_bytes()].concat();
    let reply = worker.call(&request, 16);
    std::fs::remove_file(&path).unwrap();
    drop(bootstrap);
    let id = String::from_utf8(reply.unwrap().as_bytes().to_vec()).unwrap();
    (writer, id)
}

#[cfg(target_os = "linux")]
fn linux_pidfd(pid: &str) -> bool {
    let needle = format!("Pid:\t{pid}");
    std::fs::read_dir("/proc/thread-self/fdinfo")
        .unwrap()
        .flatten()
        .any(|entry| {
            std::fs::read_to_string(entry.path())
                .is_ok_and(|info| info.lines().any(|line| line == needle))
        })
}

#[cfg(unix)]
fn a_worker_starts_from_a_protected_stack() {
    use secret_protection_core::{StackProperties, run_on_protected_stack};
    // No code runs between `fork` and the start of the worker, so the stack it is started from,
    // which a forked child would find empty, does not matter.
    let run = run_on_protected_stack(256 << 10, StackProperties::default(), || {
        let mut worker = Worker::start(Options::new(), &required()).unwrap();
        worker.call(b"public", 100).unwrap().as_bytes().to_vec()
    })
    .unwrap();
    assert_eq!(run.value, b"cilbup");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
))]
#[path = "worker/linux.rs"]
mod linux;

#[cfg(unix)]
#[path = "worker/unix.rs"]
mod unix;

#[cfg(windows)]
#[path = "worker/windows.rs"]
mod windows;
