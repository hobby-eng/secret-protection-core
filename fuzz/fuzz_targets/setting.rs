//! The text of the worker's setting variable: whoever starts the program can write any. A text
//! is a setting only when it names options this crate knows and its canonical form reads the
//! same; on Unix nothing follows its two flags.
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
});
