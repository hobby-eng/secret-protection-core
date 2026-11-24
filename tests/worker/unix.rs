//! Unix worker roles: programs that start a worker from a changed state, such as closed
//! standard streams, a descriptor left open or a terminal.
use super::*;

/// `serve` closes no descriptor: the start of a worker closed what it would have inherited before
/// the program ran. A program that opened a file before it called `serve` keeps the file, and its
/// report says that its start was not clean. The test stands in for the parent, takes the report
/// and sends no request.
#[cfg(unix)]
pub(super) fn a_late_serve_closes_nothing() {
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
pub(super) fn a_program_without_a_setting_keeps_what_it_inherited() {
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
pub(super) fn a_worker_inherits_nothing_its_libraries_could_find() {
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
pub(super) fn a_program_without_streams_starts_workers() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .env(ROLE, "streamless")
        .status()
        .unwrap();
    assert!(status.success(), "{status}");
}

/// TIOCSTI: of linux/ioctls.h, and of sys/ttycom.h on macOS (`_IOW('t', 114, char)`), which
/// libc 0.2.191 lacks there.
#[cfg(target_os = "linux")]
pub(super) const TIOCSTI: libc::Ioctl = libc::TIOCSTI;
#[cfg(target_os = "macos")]
pub(super) const TIOCSTI: libc::c_ulong = 0x8001_7472;

/// A worker on the terminal gets the terminal without the session that would let it type into
/// it (TIOCSTI): the `on-a-terminal` role runs on a new pseudo-terminal and checks.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn a_worker_on_a_terminal_cannot_type_into_it() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .env(ROLE, "on-a-terminal")
        .status()
        .unwrap();
    assert!(status.success(), "{status}");
}

/// The `on-a-terminal` role: its standard input is a new pseudo-terminal.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn on_a_terminal() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: posix_openpt opens a new controller, owned once below; grantpt and unlockpt take its
    // descriptor; ptsname gives a NUL-terminated name, copied at once.
    let (_controller, name) = unsafe {
        let controller = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(controller >= 0);
        let controller = OwnedFd::from_raw_fd(controller);
        assert_eq!(libc::grantpt(controller.as_raw_fd()), 0);
        assert_eq!(libc::unlockpt(controller.as_raw_fd()), 0);
        let name = libc::ptsname(controller.as_raw_fd());
        assert!(!name.is_null());
        (controller, std::ffi::CStr::from_ptr(name).to_owned())
    };
    // SAFETY: open reads the NUL-terminated name; dup2 and close take the descriptors it made.
    unsafe {
        let terminal = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(terminal >= 0);
        assert_eq!(libc::dup2(terminal, libc::STDIN_FILENO), libc::STDIN_FILENO);
        libc::close(terminal);
    }
    let mut worker = Worker::start_on_terminal(Options::new(), &required()).unwrap();
    assert_eq!(worker.call(b"session", 10).unwrap().as_bytes(), b"true");
    let stderr = worker.call(b"stderr", 100).unwrap();
    assert_eq!(stderr.as_str().unwrap(), identity(libc::STDIN_FILENO));
    // Refused: on Linux by the filter, on macOS by the kernel, as the terminal is not the
    // worker's own.
    let typed = worker.call(b"type", 10).unwrap();
    assert_eq!(typed.as_str().unwrap(), libc::EACCES.to_string());
    let mut waiting: libc::c_int = 0;
    // SAFETY: FIONREAD writes the number of bytes waiting into an int that lives for the call.
    let asked = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::FIONREAD, &raw mut waiting) };
    assert_eq!(asked, 0);
    assert_eq!(waiting, 0, "input reached the terminal");
}

/// The `streamless` role.
#[cfg(unix)]
pub(super) fn streamless() {
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
pub(super) fn kept() {
    let left: i32 = std::env::var(KEPT).unwrap().parse().unwrap();
    // SAFETY: fcntl with F_GETFD takes integers and only reads.
    assert_ne!(unsafe { libc::fcntl(left, libc::F_GETFD) }, -1);
}
