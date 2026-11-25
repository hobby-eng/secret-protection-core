//! Reports each integration check, including why a whole check was skipped or a subcase
//! could not run. A partially exercised check prints its reason alongside the result.
#![allow(dead_code, reason = "each test program uses a part of the runner")]

use std::process::ExitStatus;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The exit status of a role that cannot make its check on this system.
pub(crate) const SKIPPED: i32 = 77;

/// Targets that have this crate's Linux seccomp filter.
pub(crate) const LINUX_SECCOMP: bool = cfg!(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
));

/// What the check now running could not do here: all of it, or a part.
enum Mark {
    Whole(String),
    Part(String),
}

static MARK: Mutex<Option<Mark>> = Mutex::new(None);

/// How many checks failed so far; [`finish`] fails the program when any did.
static FAILED: AtomicUsize = AtomicUsize::new(0);

/// The process that runs the checks.
#[cfg(unix)]
static RUNNER: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// Runs one check unless a `--skip <part of its name>` argument leaves it out, as the standard
/// harness does. A sanitizer puts its own `mlock` in, which locks nothing, so the checks of
/// locked memory have to be left out under it. A failed check does not stop the next ones, as
/// in the standard harness: [`finish`] fails the program at the end.
pub(crate) fn run(name: &str, check: fn()) {
    #[cfg(unix)]
    RUNNER.get_or_init(std::process::id);
    let arguments: Vec<String> = std::env::args().collect();
    let left_out = arguments
        .windows(2)
        .any(|pair| pair[0] == "--skip" && name.contains(pair[1].as_str()));
    if left_out {
        return println!("test {name} ... ignored");
    }
    if std::panic::catch_unwind(check).is_err() {
        #[cfg(unix)]
        end_a_forked_child();
        FAILED.fetch_add(1, Ordering::SeqCst);
        MARK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        return println!("test {name} ... FAILED");
    }
    match MARK.lock().unwrap().take() {
        Some(Mark::Whole(reason)) => println!("test {name} ... ignored, {reason}"),
        Some(Mark::Part(reason)) => println!("test {name} ... ok, but not checked here: {reason}"),
        None => println!("test {name} ... ok"),
    }
}

/// Ends a child of `fork` whose part of a check panicked, at once and without its parent's exit
/// handlers: the parent reads the failure from its exit status, and the next checks are the
/// parent's to run.
#[cfg(unix)]
fn end_a_forked_child() {
    if RUNNER
        .get()
        .is_some_and(|&runner| runner != std::process::id())
    {
        // SAFETY: _exit ends this process at once and takes no pointer.
        unsafe { libc::_exit(101) };
    }
}

/// Fails the program when a check failed, once every check had its turn.
pub(crate) fn finish() {
    let failed = FAILED.load(Ordering::SeqCst);
    assert_eq!(failed, 0, "{failed} checks failed: see FAILED above");
}

/// Marks the check now running as one this system cannot make, for `reason`.
pub(crate) fn skip(reason: &str) {
    *MARK.lock().unwrap() = Some(Mark::Whole(reason.to_owned()));
}

/// Ends a role that cannot make its check on this system: its parent reports the check skipped.
#[allow(
    clippy::print_stderr,
    reason = "the reason goes to the parent on standard error"
)]
pub(crate) fn skip_role(reason: &str) -> ! {
    eprintln!("{reason}");
    std::process::exit(SKIPPED)
}

/// The prefix of a line on standard error by which a role says that a part was not checked.
pub(crate) const NOT_CHECKED: &str = "not checked here: ";

/// Reads how a role ended: whether it could make its check at all, and any part it could not,
/// which the check now running is marked with. Asserts that it did not fail.
pub(crate) fn role_ended(role: &str, status: ExitStatus, stderr: &[u8]) {
    let said = String::from_utf8_lossy(stderr);
    if status.code() == Some(SKIPPED) {
        return skip(said.trim());
    }
    assert!(status.success(), "{role}: {status} {said}");
    if let Some(part) = said.lines().find_map(|line| line.strip_prefix(NOT_CHECKED)) {
        *MARK.lock().unwrap() = Some(Mark::Part(part.to_owned()));
    }
}

/// A tracer outside a nested Linux PID namespace is invisible to the process.
#[cfg(target_os = "linux")]
pub(crate) fn initial_pid_namespace() -> bool {
    std::fs::read_link("/proc/self/ns/pid").is_ok_and(|link| link.as_os_str() == "pid:[4026531836]")
}

#[cfg(target_os = "linux")]
pub(crate) fn check_memory_reading(isolation: secret_protection_core::Isolation) {
    use secret_protection_core::{Outcome, Protection};
    let expected = if initial_pid_namespace() {
        Outcome::Confirmed
    } else {
        Outcome::Unknown
    };
    assert_eq!(isolation.outcome(Protection::NoMemoryReading), expected);
}
