//! Round-trips the isolation portion of a worker report. The clean-start flag and the
//! parent's admission decision are checked separately by worker tests.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_protection_core::fuzzing;

fuzz_target!(|bytes: &[u8]| {
    if let Some(isolation) = fuzzing::report(bytes) {
        assert_eq!(fuzzing::report_bytes(isolation), bytes);
    }
});
