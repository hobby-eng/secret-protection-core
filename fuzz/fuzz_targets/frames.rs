//! The frames of a worker's channel: four bytes of length, little-endian, then that many bytes.
//! The worker reads requests from its parent and the parent reads answers from its worker; either
//! side may be the one an attacker holds. The first byte sets the longest frame allowed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_protection_core::fuzzing;

fuzz_target!(|bytes: &[u8]| {
    let Some((&most, input)) = bytes.split_first() else {
        return;
    };
    let most = usize::from(most) * 64;

    // The worker takes whole frames from the front of the input, none longer than allowed, and
    // answers each in a frame of its own.
    let (taken, written) = fuzzing::requests(input, most);
    let mut read = Vec::new();
    let mut answered = Vec::new();
    for request in &taken {
        assert!(request.len() <= most);
        let length = u32::try_from(request.len()).unwrap().to_le_bytes();
        read.extend_from_slice(&length);
        read.extend_from_slice(request);
        answered.extend_from_slice(&length);
        answered.extend(request.iter().rev());
    }
    assert!(input.starts_with(&read));
    assert_eq!(written, answered);

    // The parent takes one answer of at most `most` bytes, exactly as the frame gives it.
    if let Ok(answer) = fuzzing::answer(input, most) {
        assert!(answer.len() <= most);
        assert_eq!(input.get(4..4 + answer.len()), Some(answer.as_slice()));
    }
});
