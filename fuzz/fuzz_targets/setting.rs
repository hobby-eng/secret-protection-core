//! The text of the worker's setting variable: whoever starts the program can write any. A text
//! is a setting only when it names options this crate knows and its canonical form reads the
//! same; on Unix its rest names only descriptors above standard error, which a worker closes
//! before `main`, one for each part.
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
        let again = format!("{options},{},{rest}", u8::from(terminal));
        assert_eq!(fuzzing::setting(&again), read);
    }
    #[cfg(unix)]
    if let Some((_, _, rest)) = read {
        let named = fuzzing::inherited(rest);
        assert!(named.iter().all(|&descriptor| descriptor > 2));
        assert_eq!(
            named.len(),
            rest.split('.').filter(|part| !part.is_empty()).count()
        );
    }
});
