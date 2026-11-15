//! A linked-library initializer that reuses an inherited descriptor number for its own file.
#![allow(
    unsafe_code,
    reason = "the initializer reads a number and uses close/open before main"
)]

use std::sync::atomic::{AtomicBool, Ordering};

static REUSED: AtomicBool = AtomicBool::new(false);

extern "C" fn initialize() {
    // SAFETY: the name is NUL-terminated; when present, its value is a descriptor number supplied
    // by the synthetic parent. The calls operate on that descriptor alone.
    unsafe {
        let value = libc::getenv(c"AUD012_FD".as_ptr());
        if value.is_null() {
            return;
        }
        let Ok(text) = std::ffi::CStr::from_ptr(value).to_str() else {
            return;
        };
        let Ok(descriptor) = text.parse::<i32>() else {
            return;
        };
        libc::close(descriptor);
        let opened = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        REUSED.store(opened == descriptor, Ordering::Relaxed);
    }
}

#[used]
#[unsafe(link_section = ".init_array")]
static INITIALIZE: extern "C" fn() = initialize;

/// Returns 1 when the library's initializer reused the descriptor supplied by the synthetic parent.
#[unsafe(no_mangle)]
pub extern "C" fn aud012_reused() -> i32 {
    i32::from(REUSED.load(Ordering::Relaxed))
}
