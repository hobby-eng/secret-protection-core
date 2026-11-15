//! The bytes a parent reads as its worker's report. A worker that fails, or one that someone else
//! controls, can write any; only bytes a report can be are taken, and they read back as written.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_protection_core::fuzzing;

fuzz_target!(|bytes: &[u8]| {
    if let Some(isolation) = fuzzing::report(bytes) {
        assert_eq!(fuzzing::report_bytes(isolation), bytes);
    }
});
