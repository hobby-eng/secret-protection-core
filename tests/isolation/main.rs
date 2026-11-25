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
              check panics, as in a test harness"
)]

#[path = "../support/run.rs"]
mod support;
use support::run;

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
    let role = std::env::var(ROLE);
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little"
    ))]
    if run_filter_role(role.as_deref().unwrap_or_default()) {
        return;
    }
    match role.as_deref() {
        Ok("isolated") => isolated(),
        #[cfg(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64"),
                target_endian = "little"
            ),
            target_os = "macos"
        ))]
        Ok("folders") => folders::folders_role(),
        #[cfg(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64"),
                target_endian = "little"
            ),
            target_os = "macos"
        ))]
        Ok("stale-folder") => folders::stale_folder_role(),
        #[cfg(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64"),
                target_endian = "little"
            ),
            target_os = "macos"
        ))]
        Ok("shared-memory") => folders::shared_memory_role(),
        Ok("idle") => idle(),
        #[cfg(windows)]
        Ok("impersonating-sibling") => windows::an_impersonating_sibling_keeps_its_own_integrity(),
        #[cfg(target_os = "linux")]
        Ok("traced") => linux::traced_role(false),
        #[cfg(target_os = "linux")]
        Ok("traced-sibling") => linux::traced_role(true),
        #[cfg(target_os = "linux")]
        Ok("locked") => linux::locked_role(),
        #[cfg(not(target_arch = "wasm32"))]
        Ok("writer") => writer(),
        #[cfg(unix)]
        Ok("unread-writer") => unread_writer(),
        _ if cfg!(target_family = "wasm") => {
            run(
                "WebAssembly applies nothing and says so",
                webassembly_applies_nothing_and_says_so,
            );
            support::finish();
        }
        _ => checks(),
    }
}

/// Dispatches the Linux roles that require the generated seccomp filter.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
))]
fn run_filter_role(role: &str) -> bool {
    match role {
        "folders-then-threads" => folders::folders_then_threads_role(),
        "sibling-then-folders" => folders::sibling_then_folders_role(),
        "foreign" => under_a_foreign_filter(),
        "forked" => linux::forked_role(),
        "unlayered" => linux::unlayered_role(),
        "unlisted" => linux::unlisted_role(),
        "old-marks" => linux::old_marks_role(),
        "all-threads" => linux::threads_role(true),
        "one-thread-only" => linux::threads_role(false),
        "foreign-sibling" => linux::foreign_sibling_role(),
        "repeated" => linux::repeated_role(),
        "forked-threads" => linux::forked_threads_role(),
        "policed" => linux::policed_role(),
        "undumpable-refused" => linux::undumpable_refused_role(),
        "own-pids" => linux::own_pids_role(),
        "relayered" => linux::relayered_role(),
        "unmasked" => linux::unmasked_role(),
        "speculating" => linux::speculation_role(true),
        "unspeculated" => linux::speculation_role(false),
        "refused" => refused_filter_role(),
        _ => return false,
    }
    true
}

/// The checks that each run a Linux role in a child of its own.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
))]
fn linux_role_checks() {
    run(
        "a forked child does not take its parent's signal rule or memory lock for its own",
        || linux::role_ends_well("forked"),
    );
    run(
        "a refused dumpable change keeps the process out of a user namespace",
        || linux::role_ends_well("undumpable-refused"),
    );
    run(
        "the signal option alone refuses owners and O_ASYNC and leaves locks and flags",
        linux::the_signal_option_alone_refuses_owners_and_async,
    );
    run(
        "a refusal by someone else's policy confirms no protection of this crate's",
        || linux::role_ends_well("policed"),
    );
    run(
        "a PID namespace of its own leaves the reading of memory unknown",
        || linux::role_ends_well("own-pids"),
    );
    run(
        "a Landlock layer the kernel refused once is tried again",
        || linux::role_ends_well("relayered"),
    );
    run(
        "with all_threads the filter and the layer reach a thread that was there before",
        || linux::role_ends_well("all-threads"),
    );
    run(
        "without all_threads a thread that was there before keeps what isolation takes",
        || linux::role_ends_well("one-thread-only"),
    );
    run(
        "a thread with a filter of its own keeps the filter on the calling thread alone",
        || linux::role_ends_well("foreign-sibling"),
    );
    run(
        "repeated calls with all_threads add no filter and keep the whole process",
        || linux::role_ends_well("repeated"),
    );
    run(
        "a child of fork does not take its parent's record of a filter on every thread",
        || linux::role_ends_well("forked-threads"),
    );
    run(
        "a secret made where signals cannot be blocked takes no secret memory",
        || linux::role_ends_well("unmasked"),
    );
    run(
        "a refused Landlock layer is not reported as a signal scope",
        || linux::role_ends_well("unlayered"),
    );
    run(
        "threads that cannot be listed leave the reading of memory unknown",
        || linux::role_ends_well("unlisted"),
    );
    run(
        "a filter with the marks of the 0.1 line does not keep this version's out",
        || linux::role_ends_well("old-marks"),
    );
    run(
        "speculation the kernel does not limit or report is not called limited",
        || {
            linux::role_ends_well("speculating");
            linux::role_ends_well("unspeculated");
        },
    );
}

/// Every check, in a process that plays no role.
fn checks() {
    #[cfg(windows)]
    run("low integrity includes impersonating threads", || {
        let output = child("impersonating-sibling").wait_with_output().unwrap();
        support::role_ended("impersonating-sibling", output.status, &output.stderr);
    });
    #[cfg(target_os = "linux")]
    if support::LINUX_SECCOMP {
        run(
            "an isolated thread is refused what the filter names and keeps what it needs",
            linux::an_isolated_thread_is_refused_what_the_filter_names,
        );
    } else {
        run(
            "an isolated Linux thread without seccomp reports its available protections",
            linux::a_thread_without_seccomp_reports_its_protections,
        );
    }
    run(
        "a process of one thread is isolated as a whole",
        a_process_of_one_thread_is_isolated_as_a_whole,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little"
    ))]
    run(
        "a filter installed by someone else does not keep this crate's out",
        a_foreign_filter_does_not_keep_this_crates_out,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little"
    ))]
    run(
        "a filter the system refuses is reported missing and tried again",
        a_refused_filter_is_reported_missing,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little"
    ))]
    run(
        "options refuse file locks and sendmsg, with one more filter at most",
        linux::options_add_one_filter_at_most,
    );
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little"
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
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little"
    ))]
    linux_role_checks();
    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_endian = "little"
        ),
        target_os = "macos"
    ))]
    folders::checks();
    #[cfg(target_os = "macos")]
    run(
        "a temporary folder that does not exist leaves the file probe its other place",
        a_missing_temporary_folder_leaves_the_file_probe_its_other_place,
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
    #[cfg(unix)]
    run(
        "a secret written where nobody reads fails, and says so",
        || role_ends_well("unread-writer"),
    );
    #[cfg(unix)]
    run(
        "the channels a process holds are listed by kind",
        the_channels_a_process_holds_are_listed_by_kind,
    );
    support::finish();
}

/// Starts this program again in `role` and expects it to end well.
#[cfg(unix)]
fn role_ends_well(role: &str) {
    let output = child(role).wait_with_output().unwrap();
    support::role_ended(role, output.status, &output.stderr);
}

/// The `unread-writer` role: standard output is a pipe whose reader is gone, so writing a secret
/// fails; the error says so, instead of the secret seeming written.
#[cfg(unix)]
fn unread_writer() {
    let mut ends = [0; 2];
    // SAFETY: pipe writes two new descriptors into the array; close and dup2 take integers.
    unsafe {
        assert_eq!(libc::pipe(ends.as_mut_ptr()), 0);
        libc::close(ends[0]);
        assert_eq!(libc::dup2(ends[1], 1), 1);
    }
    let refused = protect::write_secret("test words").map_err(|error| error.kind());
    assert_eq!(refused, Err(std::io::ErrorKind::BrokenPipe));
}

/// What a process holds open, by kind: a host looks at it after the isolation, before it reads a
/// secret.
#[cfg(unix)]
fn the_channels_a_process_holds_are_listed_by_kind() {
    use protect::ChannelKind;
    use std::os::fd::AsRawFd;
    let directory = std::fs::File::open("/").unwrap();
    let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
    let device = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    let (socket, _other) = std::os::unix::net::UnixStream::pair().unwrap();
    let (reader, _writer) = std::io::pipe().unwrap();
    let open = protect::open_channels().unwrap();
    // Shared memory is counted on Linux, Android and macOS; elsewhere the inventory says it is
    // incomplete.
    let counted = cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos"
    ));
    assert_eq!(open.complete, counted, "{open:?}");
    let kind = |descriptor: i32| {
        let found = open
            .channels
            .iter()
            .find(|channel| channel.descriptor == descriptor);
        found.map(|channel| (channel.kind, channel.writable))
    };
    assert_eq!(
        kind(directory.as_raw_fd()),
        Some((ChannelKind::Directory, Some(false)))
    );
    assert_eq!(
        kind(file.as_raw_fd()),
        Some((ChannelKind::File, Some(false)))
    );
    assert_eq!(
        kind(device.as_raw_fd()),
        Some((ChannelKind::Device, Some(true)))
    );
    assert_eq!(
        kind(socket.as_raw_fd()),
        Some((ChannelKind::Socket, Some(true)))
    );
    assert_eq!(
        kind(reader.as_raw_fd()),
        Some((ChannelKind::Pipe, Some(false)))
    );
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
    #[cfg(target_os = "macos")]
    let (_controller, other) = another_terminal();
    let isolation = Isolation::enter();
    expect_whole_process(isolation);
    #[cfg(target_os = "macos")]
    other_terminals_are_out_of_reach(&other);
    // The rule for every thread holds in a process of one thread.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use secret_protection_core::{Options, Protection};
        let required = [Protection::NoNewSockets, Protection::NoFileChanges];
        let wide = Isolation::enter_requiring_process_wide(Options::new(), &required);
        if support::LINUX_SECCOMP || cfg!(target_os = "macos") {
            assert!(wide.is_ok(), "{wide:?}");
        } else {
            assert_eq!(wide.unwrap_err().missing, required);
        }
    }
    // Linux reads back the earlier setup. On Windows a repeated standalone check can lose
    // visibility of the threads needed to confirm access control and integrity.
    #[cfg(target_os = "linux")]
    assert_eq!(Isolation::enter(), isolation);
    #[cfg(windows)]
    {
        use secret_protection_core::{Outcome, Protection};
        let again = Isolation::enter();
        for measure in isolation.measures() {
            let p = measure.protection;
            if matches!(p, Protection::LowIntegrity | Protection::NoMemoryReading)
                && again.outcome(p) == Outcome::Unknown
            {
                assert!(again.require(&[p]).is_err());
            } else {
                assert_eq!(again.outcome(p), measure.outcome, "{p:?}");
            }
        }
    }
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

/// A new pseudo-terminal, which is none of the process's own standard streams.
#[cfg(target_os = "macos")]
fn another_terminal() -> (std::os::fd::OwnedFd, std::ffi::CString) {
    use std::os::fd::FromRawFd;
    // SAFETY: posix_openpt opens a new controller, owned once below; grantpt and unlockpt take its
    // descriptor; ptsname gives a NUL-terminated name, copied at once.
    unsafe {
        let controller = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(controller >= 0);
        assert_eq!(libc::grantpt(controller), 0);
        assert_eq!(libc::unlockpt(controller), 0);
        let name = libc::ptsname(controller);
        assert!(!name.is_null());
        (
            std::os::fd::OwnedFd::from_raw_fd(controller),
            std::ffi::CStr::from_ptr(name).to_owned(),
        )
    }
}

/// The sandbox refuses to read, write or change a terminal that is not the process's own.
#[cfg(target_os = "macos")]
fn other_terminals_are_out_of_reach(name: &std::ffi::CStr) {
    for flags in [libc::O_RDONLY, libc::O_WRONLY] {
        // SAFETY: open reads the NUL-terminated name; a descriptor it gives is closed at once.
        let (opened, error) = unsafe {
            let opened = libc::open(name.as_ptr(), flags | libc::O_NOCTTY);
            let error = std::io::Error::last_os_error().raw_os_error();
            if opened >= 0 {
                libc::close(opened);
            }
            (opened, error)
        };
        assert_eq!((opened, error), (-1, Some(libc::EPERM)), "{flags}");
    }
    // SAFETY: chmod reads the NUL-terminated name.
    let changed = unsafe { libc::chmod(name.as_ptr(), 0o666) };
    let error = std::io::Error::last_os_error().raw_os_error();
    assert_eq!((changed, error), (-1, Some(libc::EPERM)));
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
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
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
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
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
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
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
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
))]
fn refused_filter_role() {
    linux::install_a_filter_refusing_filters();
    let before = seccomp_filters();
    for _ in 0..3 {
        let isolation = Isolation::enter();
        crate::support::check_memory_reading(isolation);
        assert!(isolation.no_core_dumps, "{isolation:?}");
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

/// A temporary folder that does not exist leaves the file probe its other place: file changes
/// still read as refused.
#[cfg(target_os = "macos")]
fn a_missing_temporary_folder_leaves_the_file_probe_its_other_place() {
    let output = Command::new(std::env::current_exe().unwrap())
        .env(ROLE, "isolated")
        .env("TMPDIR", "/secret-protection-core-test-no-such-folder")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.starts_with(b"entered\n"));
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
                && isolation.desktop_restricted,
            "{isolation:?}"
        );
        use secret_protection_core::{Outcome, Protection};
        assert!(windows::primary_is_low());
        let level = isolation.outcome(Protection::LowIntegrity);
        assert!(
            matches!(level, Outcome::Confirmed | Outcome::Unknown),
            "{level:?}"
        );
        assert_eq!(
            isolation.require(&[Protection::LowIntegrity]).is_ok(),
            level == Outcome::Confirmed
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

#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little"
    ),
    target_os = "macos"
))]
mod folders;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(windows)]
mod windows;
