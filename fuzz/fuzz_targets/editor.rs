//! What `read_hidden_line` makes of typed input: a Unix terminal sends UTF-8, the Windows console
//! UTF-16, and the editor drops escape sequences and control keys. The first byte sets the
//! line's capacity, the second which input the rest is.
#![no_main]

use std::io::ErrorKind;

use libfuzzer_sys::fuzz_target;
use secret_protection_core::fuzzing;

fuzz_target!(|bytes: &[u8]| {
    let [capacity, kind, input @ ..] = bytes else {
        return;
    };
    let capacity = usize::from(*capacity);
    let (ended, line) = if kind & 1 == 0 {
        fuzzing::edit_utf8(input, capacity)
    } else {
        let units: Vec<u16> = input
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .collect();
        fuzzing::edit_utf16(&units, capacity)
    };
    // The line never outgrows its capacity and holds no control character. The only errors are
    // input that is no text and a line longer than allowed.
    assert!(line.len() <= capacity);
    assert!(!line.chars().any(char::is_control));
    if let Err(error) = ended {
        assert!(matches!(
            error.kind(),
            ErrorKind::InvalidData | ErrorKind::InvalidInput
        ));
    }
});
