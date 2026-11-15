//! Checks that worker startup does not close a descriptor reused by a linked library.
#![allow(
    unsafe_code,
    reason = "the synthetic process uses fcntl to control descriptor inheritance"
)]
#![allow(
    clippy::print_stderr,
    reason = "the audit command reports the observed descriptor state"
)]

use std::error::Error;
use std::io;

#[link(name = "secret_protection_core_aud_012_library")]
unsafe extern "C" {
    fn aud012_reused() -> i32;
}

fn main() -> Result<(), Box<dyn Error>> {
    // Use the crate in the executable, so that its pre-main initializer cannot be dropped.
    let _ = secret_protection_core::open_channels();
    if std::env::var_os("SECRET_PROTECTION_CORE_WORKER").is_some() {
        let descriptor: i32 = std::env::var("AUD012_FD")?.parse()?;
        // SAFETY: the linked library's function only reads its own atomic flag.
        if unsafe { aud012_reused() } == 0 {
            return Err(io::Error::other("the linked-library constructor did not run").into());
        }
        // SAFETY: fcntl only reads the flags of the descriptor number supplied by the parent.
        let open = unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0;
        if !open {
            eprintln!("FAIL: worker startup closed the linked library's reused descriptor");
            return Err(io::Error::other("the library lost its descriptor").into());
        }
        eprintln!("child: the linked library's descriptor remained open");
        return Ok(());
    }
    let file = std::fs::File::open("/dev/null")?;
    use std::os::fd::AsRawFd;
    let descriptor = file.as_raw_fd();
    // SAFETY: clears close-on-exec on the synthetic descriptor so that the child inherits it.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, 0) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let status = std::process::Command::new(std::env::current_exe()?)
        .env("SECRET_PROTECTION_CORE_WORKER", format!("0,0,{descriptor}"))
        .env("AUD012_FD", descriptor.to_string())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("child failed with {status}")).into());
    }
    eprintln!("PASS: worker startup preserved the descriptor reused by the linked library");
    Ok(())
}
