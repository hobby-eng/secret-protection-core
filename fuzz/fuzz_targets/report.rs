//! A worker's startup report as its parent reads it: one byte for each protection, its outcome
//! and reach, then the clean-start flag. Whatever is understood encodes back to the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_protection_core::fuzzing;

fuzz_target!(|bytes: &[u8]| {
    if let Some(isolation) = fuzzing::report(bytes) {
        assert_eq!(fuzzing::report_bytes(isolation), bytes);
    }
    if let Some((isolation, clean)) = fuzzing::understood(bytes) {
        let mut again = fuzzing::report_bytes(isolation);
        again.push(u8::from(clean));
        assert_eq!(again, bytes);
        assert_eq!(bytes.len(), fuzzing::REPORT_BYTES);
    }
});
