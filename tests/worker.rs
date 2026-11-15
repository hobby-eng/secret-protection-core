//! The worker process: started, cleaned up and isolated before it gets anything, answering
//! requests, with no environment, descriptor or terminal of its parent's but its pipes; stopped
//! before any request when it is not clean or lacks a required protection; and ended at once when
//! a call fails. The program is both sides: its `main` calls `serve` first, as a program using the
//! crate does.
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
              check ends it, as in a test harness"
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
/// The inodes of the pipes above standard error that were open when this program's first code
/// ran, before `main`, as the start-up code of a library linked to it would find them; zeros
/// after the last.
#[cfg(unix)]
static PIPES_BEFORE_MAIN: [std::sync::atomic::AtomicU64; 16] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 16];

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
        if let Some(slot) = PIPES_BEFORE_MAIN.get(found).filter(|_| pipe) {
            slot.store(status.st_ino, Ordering::Relaxed);
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
            .map(|inode| inode.load(Ordering::Relaxed).to_string())
            .take_while(|inode| inode != "0")
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
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("without-listing") => return linux::without_listing(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("unwaited") => return linux::unwaited(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("separate-table") => return linux::separate_table(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("first-reply") => return linux::first_reply(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("memory-baseline") => return linux::memory_baseline(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("unexamined") => return linux::unexamined(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("without-setsid") => return linux::without_setsid(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("unsignalling") => return linux::unsignalling(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("without-null") => return linux::without_null(),
        Ok("unserved") => return unserved(),
        #[cfg(unix)]
        Ok("kept") => return kept(),
        #[cfg(unix)]
        Ok("streamless") => return streamless(),
        _ => {}
    }
    if !cfg!(any(target_os = "linux", target_os = "macos", windows)) {
        println!("test no worker starts here ... ok");
        return;
    }
    #[cfg(target_os = "linux")]
    run("a thread-scoped worker is refused before a request", || {
        let options = Options::new().refuse_dynamic_code().microsoft_signed_only();
        let refused = Worker::start(options, &[]).unwrap_err();
        let WorkerError::Missing(missing) = refused else {
            panic!("unexpected refusal: {refused}");
        };
        assert_eq!(missing.missing, [Protection::WholeProcess]);
        assert!(!missing.isolation.whole_process);
    });
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
        "a program that reaches the start of a worker before serve starts none",
        a_worker_starts_no_worker,
    );
    #[cfg(unix)]
    run(
        "a program that comes to serve with a file of its own keeps it and is not clean",
        a_late_serve_closes_nothing,
    );
    #[cfg(unix)]
    run(
        "a program whose worker variable holds no setting keeps what it inherited",
        a_program_without_a_setting_keeps_what_it_inherited,
    );
    #[cfg(unix)]
    run(
        "a worker's start-up code finds no descriptor of its parent's",
        a_worker_inherits_nothing_its_libraries_could_find,
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
        a_program_without_streams_starts_workers,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
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
}

/// What every worker must have on the systems where it starts.
fn required() -> Vec<Protection> {
    let mut required = vec![Protection::WholeProcess];
    #[cfg(target_os = "linux")]
    if support::initial_pid_namespace() {
        required.push(Protection::NoMemoryReading);
    }
    #[cfg(not(target_os = "linux"))]
    required.push(Protection::NoMemoryReading);
    if cfg!(unix) {
        required.extend([
            Protection::NoCoreDumps,
            Protection::NoNewSockets,
            Protection::NoFileChanges,
        ]);
    }
    if cfg!(any(target_os = "linux", windows)) {
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
    let mut worker = Worker::start(Options::new(), &required()).unwrap();
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
        // Its standard error goes to /dev/null; a worker on the terminal keeps its parent's.
        let null = std::fs::File::open("/dev/null").unwrap();
        let stderr = worker.call(b"stderr", 100).unwrap();
        let null = std::os::fd::AsRawFd::as_raw_fd(&null);
        assert_eq!(stderr.as_str().unwrap(), identity(null));
        // SAFETY: closes the descriptor opened above, once.
        unsafe { libc::close(leaked) };
        let mut on_terminal = Worker::start_on_terminal(Options::new(), &required()).unwrap();
        assert_eq!(
            on_terminal.call(b"session", 10).unwrap().as_bytes(),
            b"false"
        );
        let stderr = on_terminal.call(b"stderr", 100).unwrap();
        assert_eq!(stderr.as_str().unwrap(), identity(libc::STDERR_FILENO));
    }
}

/// The options of the filter, which only Linux and Android have; Android starts no worker.
#[cfg(target_os = "linux")]
fn a_worker_applies_its_options() {
    let options = Options::new().refuse_file_locks().refuse_sendmsg();
    let required = [Protection::FileLocksRefused, Protection::SendmsgRefused];
    let worker = Worker::start(options, &required).unwrap();
    assert!(worker.isolation().file_locks_refused && worker.isolation().sendmsg_refused);
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
    #[cfg(target_os = "linux")]
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

/// `serve` closes no descriptor: the start of a worker closed what it would have inherited before
/// the program ran. A program that opened a file before it called `serve` keeps the file, and its
/// report says that its start was not clean. The test stands in for the parent, takes the report
/// and sends no request.
#[cfg(unix)]
fn a_late_serve_closes_nothing() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .env(ROLE, "late")
        .env("SECRET_PROTECTION_CORE_WORKER", "0,0")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success(), "the file was closed: {output:?}");
    assert_eq!(output.stdout.len(), Protection::ALL.len() + 1);
    assert_eq!(output.stdout.last(), Some(&0), "it calls its start clean");
}

/// A text in the worker's variable that is no setting starts no worker, and nothing closes a
/// descriptor before `main`: the program keeps one its parent left it. A channel's name is no
/// part of a setting on Unix, nor are numbers of descriptors.
#[cfg(unix)]
fn a_program_without_a_setting_keeps_what_it_inherited() {
    // SAFETY: dup takes an integer and returns a new descriptor without close-on-exec.
    let left = unsafe { libc::dup(0) };
    assert!(left > 2);
    let named = format!("0,0,{left}");
    for text in ["none", "", "0,2", "64,0", "0,0,channel", &named] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .env(ROLE, "kept")
            .env(KEPT, left.to_string())
            .env("SECRET_PROTECTION_CORE_WORKER", text)
            .status()
            .unwrap();
        assert!(status.success(), "{text:?} closed what the program had");
    }
    // SAFETY: closes the descriptor made above, which nothing else owns.
    unsafe { libc::close(left) };
}

/// The start-up code of a worker, as that of a library linked to the program, finds no descriptor
/// of its parent's: the start closed them before the program ran, not by their numbers after. A
/// pipe the parent leaves open is looked for among the pipes the worker had before `main`.
#[cfg(unix)]
fn a_worker_inherits_nothing_its_libraries_could_find() {
    let mut ends = [0; 2];
    // SAFETY: pipe writes two new descriptors without close-on-exec, closed below.
    assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
    // SAFETY: an all-zero `stat` is valid, and fstat writes it for the descriptor or fails.
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    assert_eq!(unsafe { libc::fstat(ends[0], &mut status) }, 0);
    let mut worker = Worker::start(Options::new(), &required()).unwrap();
    let found = worker.call(b"pipes before main", 1000).unwrap();
    let found = found.as_str().unwrap();
    let parents = status.st_ino.to_string();
    assert!(!found.split(',').any(|inode| inode == parents), "{found}");
    for end in ends {
        // SAFETY: closes a descriptor made above, once.
        unsafe { libc::close(end) };
    }
}

/// A program started with its standard streams closed makes the worker's pipes there, at 0 to 2,
/// and must move them before it hands them on. The `streamless` role closes them and starts a
/// worker of each kind; its exit says whether both answered.
#[cfg(unix)]
fn a_program_without_streams_starts_workers() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .env(ROLE, "streamless")
        .status()
        .unwrap();
    assert!(status.success(), "{status}");
}

/// The `streamless` role.
#[cfg(unix)]
fn streamless() {
    for stream in 0..=2 {
        // SAFETY: closes a standard stream of this process, which nothing here uses again.
        unsafe { libc::close(stream) };
    }
    let mut worker = Worker::start(Options::new(), &required()).unwrap();
    assert_eq!(worker.call(b"public", 100).unwrap().as_bytes(), b"cilbup");
    let mut on_terminal = Worker::start_on_terminal(Options::new(), &required()).unwrap();
    assert_eq!(
        on_terminal.call(b"public", 100).unwrap().as_bytes(),
        b"cilbup"
    );
}

/// The `kept` role: the descriptor its parent left it is still open.
#[cfg(unix)]
fn kept() {
    let left: i32 = std::env::var(KEPT).unwrap().parse().unwrap();
    // SAFETY: fcntl with F_GETFD takes integers and only reads.
    assert_ne!(unsafe { libc::fcntl(left, libc::F_GETFD) }, -1);
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
    });
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
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "worker/linux.rs"]
mod linux;
