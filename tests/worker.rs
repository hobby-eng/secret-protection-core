//! The worker process: started, isolated before it gets anything, answering requests, with no
//! environment, descriptor or terminal of its parent's but its pipes, and stopped before any
//! request when a protection the parent requires does not hold. The program is both: its `main`
//! calls `serve` first, as a program using the crate does.
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

use secret_protection_core::{
    Keystroke, Options, Protection, Secret, SecretLine, Worker, WorkerError, serve,
};

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
        .map(i32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn main() {
    if serve(answer) {
        return;
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
        "an answer longer than allowed is refused",
        a_long_answer_is_refused,
    );
}

fn run(name: &str, check: fn()) {
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
        required.push(Protection::SpeculationLimited);
    }
    if cfg!(windows) {
        required.push(Protection::NoNewSockets);
    }
    required
}

fn a_worker_answers_isolated() {
    let mut worker = Worker::start(Options::new(), &required()).unwrap();
    assert!(worker.isolation().whole_process, "{worker:?}");
    assert_eq!(worker.call(b"public", 100).unwrap().as_bytes(), b"cilbup");
    // Keystrokes, as a window sends them.
    let mut out = [0; 5];
    let bytes = Keystroke::Char('ж').to_bytes(&mut out).to_vec();
    assert_eq!(worker.call(&bytes, 10).unwrap().as_bytes(), b"1");
    assert_eq!(worker.call(b"", 10).unwrap().as_bytes(), b"");
}

fn a_worker_gets_nothing_but_its_pipes() {
    // A descriptor opened without close-on-exec, which a started program would inherit.
    #[cfg(unix)]
    // SAFETY: dup takes an integer and returns a new descriptor, closed below.
    let leaked = unsafe { libc::dup(0) };
    let mut worker = Worker::start(Options::new(), &required()).unwrap();
    assert_eq!(
        worker.call(b"environment", 1000).unwrap().as_bytes(),
        b"SECRET_PROTECTION_CORE_WORKER"
    );
    #[cfg(unix)]
    {
        assert_eq!(
            worker.call(b"descriptors", 100).unwrap().as_bytes(),
            b"0,1,2"
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
        // Without the options neither holds.
        let plain = Worker::start(Options::new(), &[]).unwrap();
        assert!(!plain.isolation().file_locks_refused && !plain.isolation().sendmsg_refused);
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
    match Worker::start(Options::new(), &[Protection::WholeProcess, impossible]) {
        Err(WorkerError::Missing(missing)) => {
            assert_eq!(missing.missing, [impossible]);
            assert!(missing.isolation.whole_process);
        }
        other => panic!("{other:?}"),
    }
}

fn a_long_answer_is_refused() {
    let mut worker = Worker::start(Options::new(), &[]).unwrap();
    let refused = worker
        .call(b"large", 99)
        .map(|_| ())
        .map_err(|error| error.kind());
    assert_eq!(refused, Err(std::io::ErrorKind::InvalidData));
    // The rest of that answer still waits: every later call is refused too.
    let refused = worker
        .call(b"public", 100)
        .map(|_| ())
        .map_err(|error| error.kind());
    assert_eq!(refused, Err(std::io::ErrorKind::InvalidData));
}
