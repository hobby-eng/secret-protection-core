//! The text of the worker's setting variable: whoever starts the program can write any. A text
//! is a setting only when it names options this crate knows and its canonical form reads the
//! same; on Unix nothing follows its two flags, and on Windows a pipe and a nonce do.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_protection_core::fuzzing;

fuzz_target!(|bytes: &[u8]| {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let read = fuzzing::setting(text);
    if let Some((options, terminal, rest)) = read {
        assert_eq!(fuzzing::options_again(options), options);
        let flags = format!("{options},{}", u8::from(terminal));
        let again = if cfg!(windows) {
            format!("{flags},{rest}")
        } else {
            flags
        };
        assert_eq!(again, text);
    }
    #[cfg(unix)]
    if let Some((_, _, rest)) = read {
        assert!(rest.is_empty());
    }
    // The Windows channel, read on any system: the pipe's name and a nonce, each 128 bits in
    // lowercase hex, and never for a worker on the terminal.
    assert!(!fuzzing::windows_channel(true, Some(text)));
    if fuzzing::windows_channel(false, Some(text)) {
        let (name, nonce) = text.split_once(',').unwrap();
        let hex = |part: &str| {
            part.len() == 32 && part.bytes().all(|d| matches!(d, b'0'..=b'9' | b'a'..=b'f'))
        };
        assert!(hex(name.strip_prefix(fuzzing::PIPE_PREFIX).unwrap()) && hex(nonce));
    }
});
