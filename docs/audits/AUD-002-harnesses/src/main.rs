//! Reproductions for AUD-002 of secret-protection-core, using synthetic data only.
#![allow(
    clippy::print_stdout,
    reason = "an audit command reports the behavior it observed"
)]

use std::error::Error;

#[cfg(target_os = "linux")]
mod linux;

fn answer(request: &[u8]) -> secret_protection_core::Secret {
    #[cfg(target_os = "linux")]
    if let Some(bytes) = linux::answer(request) {
        return secret_from(bytes);
    }
    let bytes = if request == b"large" {
        vec![b'x'; 1 << 20]
    } else {
        Vec::new()
    };
    secret_from(bytes)
}

fn secret_from(bytes: Vec<u8>) -> secret_protection_core::Secret {
    let mut secret = secret_protection_core::Secret::with_capacity(bytes.len());
    if secret.push(&bytes).is_err() {
        return secret_protection_core::Secret::with_capacity(0);
    }
    secret
}

fn worker_drop() -> Result<(), Box<dyn Error>> {
    use secret_protection_core::{Options, Worker};

    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(3));
        println!("FAIL: dropping a worker after an oversized answer deadlocked");
        std::process::exit(1);
    });
    let mut worker = Worker::start(Options::new(), &[])?;
    let error = worker.call(b"large", 1024).err().ok_or_else(|| {
        std::io::Error::other("the oversized answer was accepted instead of refused")
    })?;
    if error.kind() != std::io::ErrorKind::InvalidData {
        return Err(error.into());
    }
    drop(worker);
    println!("PASS: dropping the worker returned");
    Ok(())
}

fn stack_overflow() -> Result<(), Box<dyn Error>> {
    let outcome = std::panic::catch_unwind(|| {
        secret_protection_core::run_on_protected_stack(usize::MAX, || {})
    });
    if outcome.is_err() {
        println!("FAIL: an overflowing stack size panicked instead of returning an error");
        return Err(std::io::Error::other("the protected-stack constructor panicked").into());
    }
    let result = outcome.map_err(|_| std::io::Error::other("unreachable panic state"))?;
    if result.is_ok() {
        return Err(std::io::Error::other("usize::MAX was accepted as a stack size").into());
    }
    println!("PASS: an overflowing stack size returned an error");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    if secret_protection_core::serve(answer) {
        return Ok(());
    }
    let mode = std::env::args()
        .nth(1)
        .ok_or_else(|| std::io::Error::other("a mode is required"))?;
    match mode.as_str() {
        "worker-drop" => worker_drop(),
        "stack-overflow" => stack_overflow(),
        #[cfg(target_os = "linux")]
        "pidfd-signal" => linux::pidfd_signal(),
        #[cfg(target_os = "linux")]
        "ipc" => linux::ipc(),
        #[cfg(target_os = "linux")]
        "inherited-fd" => linux::inherited_fd(),
        _ => Err(std::io::Error::other("unknown mode").into()),
    }
}
