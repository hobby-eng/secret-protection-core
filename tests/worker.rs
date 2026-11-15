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

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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
/// How long such a worker stays, at most: beyond the two seconds its parent gives it.
const LINGER_SECONDS: u32 = 4;

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
        // SAFETY: getsid and getpid take integers and touch no memory.
        b"session" => (unsafe { libc::getsid(0) == libc::getpid() }).to_string(),
        b"large" => "x".repeat(100),
        b"huge" => "x".repeat(HUGE),
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

fn main() {
    // The `late` role opens a file of its own before it comes to `serve`.
    #[cfg(unix)]
    let early = (std::env::var(ROLE).as_deref() == Ok("late"))
        .then(|| std::fs::File::open("/dev/null").unwrap());
    if serve(MOST, answer) {
        // `serve` closed nothing: the file the program opened first is still its own.
        #[cfg(unix)]
        if let Some(file) = early {
            std::process::exit(i32::from(file.metadata().is_err()));
        }
        // A worker that was asked to linger does not end when its pipes close.
        if LINGERS.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(LINGER_SECONDS.into()));
        }
        return;
    }
    match std::env::var(ROLE).as_deref() {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("without-close-range") => return linux::without_close_range(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("without-listing") => return linux::without_listing(),
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
        _ => {}
    }
    if !cfg!(any(target_os = "linux", target_os = "macos", windows)) {
        println!("test no worker starts here ... ok");
        return;
    }
    run(
        "a worker answers what it is asked, isolated",
        a_worker_answers_isolated,
    );
    run(
        "a worker gets nothing of its parent's but its pipes",
        a_worker_gets_nothing_but_its_pipes,
    );
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
        "a worker that does not end by itself is killed after a second",
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
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        run(
            "without close_range a worker closes what it inherited one by one",
            || linux::role("without-close-range"),
        );
        run(
            "a worker that cannot list what it inherited is refused",
            || linux::role("without-listing"),
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
            "without /dev/null a worker that serves no more closes its pipes",
            || linux::role("without-null"),
        );
    }
}

/// Runs one check unless a `--skip <part of its name>` argument leaves it out, as the standard
/// harness does. A sanitizer puts its own `mlock` in, which locks nothing, so the checks of
/// locked memory have to be left out under it.
fn run(name: &str, check: fn()) {
    let arguments: Vec<String> = std::env::args().collect();
    let skipped = arguments
        .windows(2)
        .any(|pair| pair[0] == "--skip" && name.contains(pair[1].as_str()));
    if skipped {
        return println!("test {name} ... ignored");
    }
    check();
    println!("test {name} ... ok");
}

/// What every worker must have on the systems where it starts.
fn required() -> Vec<Protection> {
    let mut required = vec![Protection::NoMemoryReading, Protection::WholeProcess];
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
            let state = unsafe { libc::prctl(GET, kind, 0, 0, 0) };
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
    assert!(
        names
            .split(',')
            .all(|name| name == "SECRET_PROTECTION_CORE_WORKER" || systems.contains(&name)),
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
        // SAFETY: closes the descriptor opened above, once.
        unsafe { libc::close(leaked) };
        let mut on_terminal = Worker::start_on_terminal(Options::new(), &required()).unwrap();
        assert_eq!(
            on_terminal.call(b"session", 10).unwrap().as_bytes(),
            b"false"
        );
    }
}

fn a_worker_applies_its_options() {
    if cfg!(target_os = "linux") {
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
fn within(limit: Duration, end: impl FnOnce() + Send + 'static) -> Duration {
    let started = Instant::now();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        end();
        let _ = done.send(());
    });
    finished
        .recv_timeout(limit)
        .unwrap_or_else(|_| panic!("not done within {limit:?}"));
    started.elapsed()
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
    // Dropping it returns at once: its pipes were closed, so it ended instead of waiting to write.
    let taken = within(Duration::from_secs(20), move || drop(worker));
    assert!(taken < Duration::from_millis(900), "{taken:?}");
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
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    assert_eq!(worker.call(b"linger", 10).unwrap().as_bytes(), b"lingers");
    let started = Instant::now();
    assert!(worker.call(&vec![b'x'; MOST + 1], 10).is_err());
    let taken = started.elapsed();
    assert!(taken < Duration::from_millis(2500), "{taken:?}");
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

/// `serve` closes no descriptor: what a worker inherited was closed before its `main`. A
/// program that opened a file before it called `serve` keeps the file, and its report says that
/// its start was not clean. The test stands in for the parent, takes the report and sends no
/// request.
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

/// A text in the worker's variable that is no setting starts no worker and closes nothing
/// before `main`: the program keeps a descriptor its parent left it.
#[cfg(unix)]
fn a_program_without_a_setting_keeps_what_it_inherited() {
    // SAFETY: dup takes an integer and returns a new descriptor without close-on-exec.
    let left = unsafe { libc::dup(0) };
    assert!(left > 2);
    for text in ["none", "", "0,2", "64,0"] {
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

/// The `kept` role: the descriptor its parent named is still open.
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
    let done = std::sync::Arc::new(AtomicBool::new(false));
    let stop = std::sync::Arc::clone(&done);
    let stray = std::thread::spawn(move || {
        let mut taken = 0;
        while taken < 3 && !stop.load(Ordering::Relaxed) {
            for entry in std::fs::read_dir(r"\\.\pipe\").unwrap().flatten() {
                let ours = entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("secret-protection-core.");
                if ours && let Ok(pipe) = std::fs::File::open(entry.path()) {
                    taken += 1;
                    std::thread::sleep(Duration::from_millis(20));
                    drop(pipe);
                }
            }
        }
        taken
    });
    // The thread is listing pipes by the time the worker's appears.
    std::thread::sleep(Duration::from_millis(200));
    let mut worker = Worker::start(Options::new(), &required()).unwrap();
    assert_eq!(worker.call(b"public", 100).unwrap().as_bytes(), b"cilbup");
    done.store(true, Ordering::Relaxed);
    assert!(stray.join().unwrap() > 0, "the test never took the pipe");
}

/// The `unserved` role: the worker's variable is set, and the program is past `serve`.
fn unserved() {
    let started = Instant::now();
    match Worker::start(Options::new(), &[]) {
        Err(WorkerError::Start(error)) => assert_eq!(error.kind(), std::io::ErrorKind::Other),
        other => panic!("{other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// Ending a worker never waits for ever: one that stays after its pipes close gets a second,
/// then is killed and taken off the system's list, well before it would have ended by itself.
fn a_worker_that_lingers_is_killed() {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    let before = linux::children();
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    assert_eq!(worker.call(b"linger", 10).unwrap().as_bytes(), b"lingers");
    let started = Instant::now();
    assert!(worker.end(), "the worker was not ended");
    let taken = started.elapsed();
    assert!(
        taken >= Duration::from_millis(900) && taken < Duration::from_millis(1900),
        "{taken:?}"
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    assert_eq!(linux::children(), before, "the worker is still listed");
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
mod linux {
    use super::*;

    /// The processes this thread started that are still there, ended or not.
    pub(super) fn children() -> Vec<u32> {
        let own = std::process::id();
        std::fs::read_to_string(format!("/proc/self/task/{own}/children"))
            .unwrap()
            .split_whitespace()
            .map(|pid| pid.parse().unwrap())
            .collect()
    }

    /// A failed call ends the worker before it returns: the worker is gone from the system's
    /// list while the program still holds the `Worker`.
    pub(super) fn a_failed_call_ends_the_worker_before_it_is_dropped() {
        let before = children();
        let mut worker = Worker::start(Options::new(), &[]).unwrap();
        assert_eq!(children().len(), before.len() + 1);
        assert!(worker.call(b"huge", 10).is_err());
        assert_eq!(children(), before, "the worker is still listed");
        drop(worker);
    }

    /// The `unsignalling` role: a program that isolated itself so that it signals only itself
    /// cannot kill a worker it started before. Ending the worker still returns in time, and
    /// says that the worker is left behind.
    pub(super) fn unsignalling() {
        use secret_protection_core::Isolation;
        let mut worker = Worker::start(Options::new(), &[]).unwrap();
        assert_eq!(worker.call(b"linger", 10).unwrap().as_bytes(), b"lingers");
        let isolation = Isolation::enter_with(Options::new().signals_to_self_only());
        assert!(isolation.signals_to_self_only, "{isolation:?}");
        let started = Instant::now();
        let ended = worker.end();
        let taken = started.elapsed();
        assert!(
            !ended,
            "a process that signals only itself ended its worker"
        );
        // One second of grace and no second wait, in `end` or in the drop that follows.
        assert!(
            taken >= Duration::from_millis(900) && taken < Duration::from_millis(1900),
            "{taken:?}"
        );
    }

    /// Starts this program again in a part that runs under a filter of its own, and expects it
    /// to end well.
    pub(super) fn role(name: &str) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env(ROLE, name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &raw const filter,
                    0,
                    0
                ),
                0
            );
        }
    }

    /// As on a kernel before Linux 5.9: before its `main` the worker closes each descriptor the
    /// system lists, and then sees that none is left.
    pub(super) fn without_close_range() {
        // SAFETY: dup takes an integer and returns a new descriptor, which the worker inherits.
        let leaked = unsafe { libc::dup(0) };
        assert!(leaked > 2);
        refuse(&[(libc::SYS_close_range, errno(libc::ENOSYS))]);
        let mut worker = Worker::start(Options::new(), &required()).unwrap();
        assert_eq!(
            worker.call(b"descriptors", 100).unwrap().as_bytes(),
            its_own()
        );
    }

    /// With neither `close_range` nor a readable list, the worker cannot know what it inherited:
    /// it says so, and the parent ends it before any request. A list cut short is not complete
    /// for `open_channels` either.
    pub(super) fn without_listing() {
        refuse(&[
            (libc::SYS_close_range, errno(libc::ENOSYS)),
            (libc::SYS_getdents64, errno(libc::EACCES)),
        ]);
        match Worker::start(Options::new(), &[]) {
            Err(WorkerError::Unclean) => {}
            other => panic!("{other:?}"),
        }
        let open = secret_protection_core::open_channels().unwrap();
        assert!(!open.complete, "{open:?}");
    }

    /// Where /dev/null cannot be opened, a worker that serves no more closes its pipes outright:
    /// the parent's call fails at once, long before the worker ends by itself.
    pub(super) fn without_null() {
        refuse_read_write_opens();
        let mut worker = Worker::start(Options::new(), &[]).unwrap();
        assert_eq!(worker.call(b"linger", 10).unwrap().as_bytes(), b"lingers");
        let started = Instant::now();
        assert!(worker.call(&vec![b'x'; MOST + 1], 10).is_err());
        let taken = started.elapsed();
        assert!(taken < Duration::from_millis(2500), "{taken:?}");
    }

    /// A worker that cannot leave its parent's session says so and gets no request; on the
    /// terminal it does not try to, and starts. One that dies before it reports is an error of
    /// the start, at once: here the kernel kills it at the same call.
    pub(super) fn without_setsid() {
        refuse(&[(libc::SYS_setsid, errno(libc::EPERM))]);
        let error = Worker::start(Options::new(), &[]).unwrap_err();
        assert!(matches!(error, WorkerError::Unclean), "{error:?}");
        assert_eq!(
            error.to_string(),
            "the worker could not shed what it inherited"
        );
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
        let started = Instant::now();
        let error = Worker::start(Options::new(), &[]).unwrap_err();
        let said = error.to_string();
        assert!(said.starts_with("the worker did not start"), "{said}");
        let WorkerError::Start(cause) = error else {
            panic!("{error:?}");
        };
        assert_eq!(cause.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
