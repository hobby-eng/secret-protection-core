//! The protections of `protect::Isolation::enter` and the secret writer, checked from outside the
//! code that applies them. The program has a `main` of its own (`harness = false`): a process of
//! one thread, which a test harness never has, is a child process that it starts again in a role,
//! and so are the processes the checks look at from outside.
#![allow(
    unsafe_code,
    reason = "the checks make the system calls that a program inside the isolation could make"
)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a test program with a main of its own reports each check, as a test harness does"
)]
#![allow(
    clippy::unwrap_used,
    reason = "a test program with a main of its own, which clippy does not see as a test: a failed \
              check ends it, as in a test harness"
)]

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};

#[cfg(not(target_arch = "wasm32"))]
use secret_protection_core as protect;
use secret_protection_core::Isolation;

/// The variable that gives a child process its role.
const ROLE: &str = "SECRET_PROTECTION_CORE_TEST_ROLE";
/// The variable that gives a child process the IPC namespace of the test (Linux).
#[cfg(target_os = "linux")]
const PARENT_IPC: &str = "SECRET_PROTECTION_CORE_TEST_PARENT_IPC";

/// AddressSanitizer asks the program for its options. Its leak check needs ptrace, which an
/// isolated process refuses, and a worker gets no environment to turn it off in.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn __asan_default_options() -> *const std::ffi::c_char {
    c"detect_leaks=0".as_ptr()
}

fn main() {
    match std::env::var(ROLE).as_deref() {
        Ok("isolated") => isolated(),
        Ok("idle") => idle(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("foreign") => under_a_foreign_filter(),
        #[cfg(target_os = "linux")]
        Ok("traced") => linux::traced_role(false),
        #[cfg(target_os = "linux")]
        Ok("traced-sibling") => linux::traced_role(true),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("forked") => linux::forked_role(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("unlayered") => linux::unlayered_role(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("unlisted") => linux::unlisted_role(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("policed") => linux::policed_role(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("own-pids") => linux::own_pids_role(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("relayered") => linux::relayered_role(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("speculating") => linux::speculation_role(true),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("unspeculated") => linux::speculation_role(false),
        #[cfg(target_os = "linux")]
        Ok("locked") => linux::locked_role(),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Ok("refused") => refused_filter_role(),
        #[cfg(not(target_arch = "wasm32"))]
        Ok("writer") => writer(),
        _ if cfg!(target_family = "wasm") => run(
            "WebAssembly applies nothing and says so",
            webassembly_applies_nothing_and_says_so,
        ),
        _ => checks(),
    }
}

/// Every check, in a process that plays no role.
fn checks() {
    #[cfg(target_os = "linux")]
    run(
        "an isolated thread is refused what the filter names and keeps what it needs",
        linux::an_isolated_thread_is_refused_what_the_filter_names,
    );
    run(
        "a process of one thread is isolated as a whole",
        a_process_of_one_thread_is_isolated_as_a_whole,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "a filter installed by someone else does not keep this crate's out",
        a_foreign_filter_does_not_keep_this_crates_out,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "a filter the system refuses is reported missing and tried again",
        a_refused_filter_is_reported_missing,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "options refuse file locks and sendmsg, with one more filter at most",
        linux::options_add_one_filter_at_most,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "two threads that isolate themselves get one filter each",
        linux::sibling_threads_get_one_filter_each,
    );
    #[cfg(target_os = "linux")]
    run(
        "locking all memory is reported as the kernel answered",
        linux::locking_all_memory_is_reported,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "a forked child does not take its parent's signal rule or memory lock for its own",
        || linux::role_ends_well("forked"),
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "a refusal by someone else's policy confirms no protection of this crate's",
        || linux::role_ends_well("policed"),
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "a PID namespace of its own leaves the reading of memory unknown",
        || linux::role_ends_well("own-pids"),
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "a Landlock layer the kernel refused once is tried again",
        || linux::role_ends_well("relayered"),
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "a refused Landlock layer is not reported as a signal scope",
        || linux::role_ends_well("unlayered"),
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "threads that cannot be listed leave the reading of memory unknown",
        || linux::role_ends_well("unlisted"),
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    run(
        "speculation the kernel does not limit or report is not called limited",
        || {
            linux::role_ends_well("speculating");
            linux::role_ends_well("unspeculated");
        },
    );
    #[cfg(target_os = "linux")]
    run(
        "a tracer of another thread makes the whole process readable",
        || linux::a_traced_process_is_not_reported_unreadable("traced-sibling"),
    );
    #[cfg(target_os = "linux")]
    run(
        "a process with a tracer attached is not reported unreadable",
        || linux::a_traced_process_is_not_reported_unreadable("traced"),
    );
    #[cfg(not(target_arch = "wasm32"))]
    run(
        "a secret is written after the buffered public output",
        a_secret_is_written_after_the_buffered_public_output,
    );
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

/// Starts this program again in `role`, its standard streams piped.
fn child(role: &str) -> Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    #[cfg(target_os = "linux")]
    command.env(PARENT_IPC, std::fs::read_link("/proc/self/ns/ipc").unwrap());
    command
        .env(ROLE, role)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// The `isolated` role: enters the isolation, on Unix while it has one thread, checks the report,
/// says so and waits until its standard input closes, so that the test can look at it from
/// outside. On Windows, where the isolation holds for every thread, it starts a thread before the
/// call and one after, which wait with it, and runs Argon2id after the call.
fn isolated() {
    #[cfg(windows)]
    waiting_thread();
    let isolation = Isolation::enter();
    expect_whole_process(isolation);
    // A second call reads back the same, what the first one set included: on Linux the namespace,
    // on Windows the access lists and the integrity level.
    #[cfg(any(target_os = "linux", windows))]
    assert_eq!(Isolation::enter(), isolation);
    // Further calls add no filter: the kernel counts the seccomp filters of the thread, and a
    // layer each time would soon use up its limits.
    #[cfg(target_os = "linux")]
    {
        let before = seccomp_filters();
        for _ in 0..20 {
            assert_eq!(Isolation::enter(), isolation);
        }
        assert_eq!(seccomp_filters(), before);
    }
    #[cfg(windows)]
    {
        waiting_thread();
        threads_and_a_work_area_still_work();
    }
    println!("entered");
    idle();
}

/// The seccomp filters of the calling thread, as `/proc/thread-self/status` counts them (Linux
/// 5.9 and later; `None` before). `/proc/self` would show the first thread of the process.
#[cfg(target_os = "linux")]
fn seccomp_filters() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:"))
        .map(|count| count.trim().parse().unwrap())
}

/// A process that starts under a filter of someone else's, as every Android app and many
/// containers do, still gets this crate's filter, and only once.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn a_foreign_filter_does_not_keep_this_crates_out() {
    let output = child("foreign").wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The `foreign` role: installs a filter that allows every call, then enters the isolation twice.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn under_a_foreign_filter() {
    linux::install_a_foreign_filter();
    let before = seccomp_filters().map(|count| count + 1);
    let isolation = Isolation::enter();
    assert!(
        isolation.no_new_sockets && isolation.no_file_changes,
        "{isolation:?}"
    );
    assert_eq!(seccomp_filters(), before);
    assert_eq!(Isolation::enter(), isolation);
    assert_eq!(seccomp_filters(), before);
}

/// When the system refuses the filter, the report says so, and a further call tries again
/// instead of taking the refusal for a filter in place.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn a_refused_filter_is_reported_missing() {
    let output = child("refused").wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The `refused` role: a filter of someone else's refuses to install another one, as a stricter
/// sandbox might; Landlock and the dump settings still apply.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn refused_filter_role() {
    linux::install_a_filter_refusing_filters();
    let before = seccomp_filters();
    for _ in 0..3 {
        let isolation = Isolation::enter();
        assert!(
            isolation.no_core_dumps && isolation.no_memory_reading,
            "{isolation:?}"
        );
        // Without the filter none of these holds, though Landlock refuses opening a file for
        // writing.
        assert!(
            !isolation.no_new_sockets && !isolation.no_file_changes && !isolation.no_new_programs,
            "{isolation:?}"
        );
        assert_eq!(seccomp_filters(), before);
    }
}

/// Starts a thread that waits until the process ends.
#[cfg(windows)]
fn waiting_thread() {
    std::thread::spawn(|| {
        loop {
            std::thread::park();
        }
    });
}

/// The `idle` role: waits until its standard input closes.
fn idle() {
    std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
}

/// The `writer` role: public output that the standard library buffers, then a secret.
#[cfg(not(target_arch = "wasm32"))]
fn writer() {
    print!("public ");
    protect::write_secret("test words").unwrap();
    protect::write_secret("\n").unwrap();
}

fn webassembly_applies_nothing_and_says_so() {
    assert_eq!(Isolation::enter(), Isolation::default());
}

fn a_process_of_one_thread_is_isolated_as_a_whole() {
    let mut process = child("isolated");
    let mut line = String::new();
    BufReader::new(process.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    if line == "entered\n" {
        cannot_be_read_from_outside(process.id());
    }
    // Closing its standard input ends the child.
    process.stdin = None;
    let output = process.wait_with_output().unwrap();
    let errors = String::from_utf8_lossy(&output.stderr);
    eprint!("{errors}");
    assert!(output.status.success(), "the isolated process failed");
    assert_eq!(line, "entered\n");
}

#[cfg(not(target_arch = "wasm32"))]
fn a_secret_is_written_after_the_buffered_public_output() {
    let output = child("writer").wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"public test words\n");
}

/// Work started after the isolation, as a password hash starts its lanes and maps its memory:
/// threads start and a work area is mapped, written and read.
#[cfg(any(target_os = "linux", windows))]
fn threads_and_a_work_area_still_work() {
    let mut area = secret_protection_core::WorkArea::new(1 << 20).unwrap();
    area.as_mut_slice().fill(7);
    let lanes: Vec<_> = (0..4_u64)
        .map(|lane| std::thread::spawn(move || (0..1000_u64).map(|i| i * lane).sum::<u64>()))
        .collect();
    let sums: Vec<u64> = lanes.into_iter().map(|lane| lane.join().unwrap()).collect();
    assert_eq!(sums, [0, 499_500, 999_000, 1_498_500]);
    assert!(area.as_slice().iter().all(|&byte| byte == 7));
}

/// What a process of one thread reports.
fn expect_whole_process(isolation: Isolation) {
    // An Android app is never a process of one thread.
    assert_eq!(
        isolation.whole_process,
        cfg!(any(unix, windows)) && cfg!(not(target_os = "android")),
        "{isolation:?}"
    );
    #[cfg(target_os = "linux")]
    linux::expect_whole_process(isolation);
    #[cfg(target_os = "macos")]
    assert!(
        isolation.no_core_dumps
            && isolation.no_memory_reading
            && isolation.no_new_sockets
            && isolation.no_file_changes,
        "{isolation:?}"
    );
    // Error reports keep stacks and registers, and low integrity still writes where a low label
    // allows: both stay false on Windows.
    #[cfg(windows)]
    assert!(
        isolation.no_memory_reading && !isolation.no_core_dumps && !isolation.no_file_changes,
        "{isolation:?}"
    );
    // What Windows applies besides, each read back; and no program starts any more.
    #[cfg(windows)]
    {
        assert!(
            isolation.no_new_programs
                && isolation.no_planted_libraries
                && isolation.desktop_restricted
                && isolation.low_integrity,
            "{isolation:?}"
        );
        let started = Command::new(std::env::current_exe().unwrap())
            .env(ROLE, "idle")
            .spawn();
        assert!(started.is_err(), "a program started after the isolation");
    }
    // The sandbox allows no new program, which no probe confirms yet.
    #[cfg(target_os = "macos")]
    assert_eq!(
        isolation.outcome(secret_protection_core::Protection::NoNewPrograms),
        secret_protection_core::Outcome::Unknown
    );
}

/// Another program of the same user cannot read the memory of the isolated process.
fn cannot_be_read_from_outside(pid: u32) {
    #[cfg(target_os = "linux")]
    assert_eq!(
        std::fs::File::open(format!("/proc/{pid}/mem"))
            .err()
            .map(|error| error.kind()),
        Some(std::io::ErrorKind::PermissionDenied)
    );
    #[cfg(windows)]
    windows::cannot_be_opened(pid);
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = pid;
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(windows)]
mod windows;
