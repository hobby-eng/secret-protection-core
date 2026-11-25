//! The crate's checks on `wasm32-unknown-unknown`, which has no test runner of its own: each
//! export runs a group of checks and returns how many passed, and `run.mjs` compares the counts.
#![allow(unsafe_code, reason = "each check is an export with a name of its own")]

use std::{io::ErrorKind, time::Duration};

use secret_protection_core::{
    ClosedSecret, Isolation, Keystroke, Options, Secret, SecretLine, StackError, StackProperties,
    WorkArea, Worker, WorkerError, open_channels, run_on_protected_stack, with_cleared_stack,
};

/// The heap buffers: storing, refusing an overflow, truncating, work areas, closed secrets, and
/// the strict constructors, which refuse where nothing can be locked. Six checks.
#[unsafe(no_mangle)]
pub extern "C" fn buffers() -> u32 {
    let mut secret = Secret::with_capacity(8);
    let stored = secret.push(b"public").is_ok() && secret.as_bytes() == b"public";
    let overflow = secret.push(b"xab").is_err() && secret.as_bytes() == b"public";
    secret.truncate(3);
    let truncated = secret.as_bytes() == b"pub" && !secret.is_locked() && !secret.is_out_of_dumps();
    let work_area = WorkArea::new(4).is_some_and(|mut area| {
        area.as_mut_slice().copy_from_slice(b"test");
        area.as_slice() == b"test" && !area.is_locked()
    });
    let mut closed = ClosedSecret::with_capacity(4);
    let closure = closed.push(b"word").is_ok()
        && closed.read(|bytes| bytes == b"word")
        && !closed.is_closed()
        && !closed.is_locked();
    let strict = Secret::locked(4).is_err() && WorkArea::locked(4).is_err();
    count(&[stored, overflow, truncated, work_area, closure, strict])
}

/// UTF-8 editing and the keystroke frames. Four checks.
#[unsafe(no_mangle)]
pub extern "C" fn input() -> u32 {
    let mut line = SecretLine::with_capacity(4);
    let key = Keystroke::Char('é');
    let codec = Keystroke::from_bytes(key.to_bytes().as_bytes()) == Some(key);
    let accepted = line.apply(key).is_ok() && line.as_str() == "é" && line.characters() == 1;
    let refused = line.apply(Keystroke::Char('🔍')).is_err() && line.as_str() == "é";
    let removed = line.apply(Keystroke::RemoveLast).is_ok() && line.as_str().is_empty();
    count(&[codec, accepted, refused, removed])
}

/// What needs processes, stacks or channels answers `Unsupported` without trapping: every worker
/// start, timed ones with a zero and the longest deadline too, protected stacks and channels.
/// Isolation reports nothing, and a cleared stack still runs its closure. Eight checks.
#[unsafe(no_mangle)]
pub extern "C" fn fallbacks() -> u32 {
    let options = Options::new();
    let ordinary = unsupported(Worker::start(options, &[]));
    let zero = unsupported(Worker::start_within(options, &[], Duration::ZERO));
    let longest = unsupported(Worker::start_within(options, &[], Duration::MAX));
    let terminal = unsupported(Worker::start_on_terminal(options, &[]));
    let stack = matches!(
        run_on_protected_stack(32 * 1024, StackProperties::default(), || ()),
        Err(StackError::Unsupported)
    );
    let channels = open_channels().is_err_and(|error| error.kind() == ErrorKind::Unsupported);
    let cleared = with_cleared_stack(|| 42_u32) == 42;
    let isolation = Isolation::enter() == Isolation::default();
    count(&[
        ordinary, zero, longest, terminal, stack, channels, cleared, isolation,
    ])
}

fn unsupported(started: Result<Worker, WorkerError>) -> bool {
    match started {
        Err(WorkerError::Start(error)) => error.kind() == ErrorKind::Unsupported,
        _ => false,
    }
}

fn count(checks: &[bool]) -> u32 {
    checks.iter().map(|&passed| u32::from(passed)).sum()
}
