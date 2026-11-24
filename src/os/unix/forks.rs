//! Unix buffers record their fork generation. A continuing child must leave an inherited owner
//! alone. Depending on the mapping and the OS, the child may receive no pages, zeros or a copy.
#![allow(unsafe_code, reason = "pthread_atfork and write are foreign functions")]

use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// One more in each child of `fork`; the process that forks keeps its count.
static GENERATION: AtomicUsize = AtomicUsize::new(0);
static WATCHED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    /// Also the fork gate's of Linux secret memory: one declaration for the crate.
    pub(in crate::os) fn pthread_atfork(
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

/// Aborts before a continuing child can borrow its parent's mapping.
pub(crate) fn foreign() -> ! {
    const TEXT: &[u8] =
        b"secret-protection-core: a buffer made before fork was used in the child\n";
    // SAFETY: write reads bytes that live as long as the program.
    unsafe { libc::write(2, TEXT.as_ptr().cast(), TEXT.len()) };
    std::process::abort()
}
