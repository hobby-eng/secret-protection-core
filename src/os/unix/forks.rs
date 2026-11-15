//! The forks of this process, counted in each child, so that pages made before a `fork` are known
//! there: the system took them away (secret memory, macOS) or left zeros without a lock (Linux's
//! anonymous pages), and their owner must not touch them.
#![allow(unsafe_code, reason = "pthread_atfork and write are foreign functions")]

use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// One more in each child of `fork`; the process that forks keeps its count.
static GENERATION: AtomicUsize = AtomicUsize::new(0);
static WATCHED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn pthread_atfork(
        prepare: Option<unsafe extern "C" fn()>,
        parent: Option<unsafe extern "C" fn()>,
        child: Option<unsafe extern "C" fn()>,
    ) -> libc::c_int;
}

/// Runs in the child of `fork`: one atomic add, no more than a signal handler may do.
unsafe extern "C" fn forked() {
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

/// Registers the handler once: before `main` where the crate's constructor runs, else before the
/// first pages. `false` when the system refused it, and then no pages are given.
pub(crate) fn watched() -> bool {
    static WATCH: Once = Once::new();
    WATCH.call_once(|| {
        // SAFETY: registers a function that lives as long as the program.
        let registered = unsafe { pthread_atfork(None, None, Some(forked)) } == 0;
        WATCHED.store(registered, Ordering::Relaxed);
    });
    WATCHED.load(Ordering::Relaxed)
}

/// The count that pages made now carry.
pub(crate) fn generation() -> usize {
    GENERATION.load(Ordering::Relaxed)
}

/// Ends a child that reaches the bytes of pages its parent made: they are gone or zeros there,
/// and a reference to them would be undefined behaviour.
pub(crate) fn foreign() -> ! {
    const TEXT: &[u8] =
        b"secret-protection-core: a buffer made before fork was used in the child\n";
    // SAFETY: write reads bytes that live as long as the program.
    unsafe { libc::write(2, TEXT.as_ptr().cast(), TEXT.len()) };
    std::process::abort()
}
