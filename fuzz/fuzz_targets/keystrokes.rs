//! The keys a window sends to the worker for a secret field: a window someone else controls can
//! send any bytes. A line takes only keystrokes, never holds more than its capacity, and holds
//! what the keystrokes it took spell. The first byte is the capacity; then each frame is a length
//! byte and that many bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_protection_core::{Keystroke, SecretLine};

fuzz_target!(|bytes: &[u8]| {
    let Some((&capacity, mut rest)) = bytes.split_first() else {
        return;
    };
    let capacity = usize::from(capacity);
    let mut line = SecretLine::with_capacity(capacity);
    let mut model = String::new();
    while let Some((&length, after)) = rest.split_first() {
        let (frame, next) = after.split_at(usize::from(length % 7).min(after.len()));
        rest = next;
        let Some(keystroke) = Keystroke::from_bytes(frame) else {
            continue;
        };
        assert_eq!(keystroke.to_bytes().as_bytes(), frame);
        let taken = line.apply(keystroke);
        match keystroke {
            Keystroke::Char(character) => {
                let fits = model.len() + character.len_utf8() <= capacity;
                assert_eq!(taken.is_ok(), fits);
                if fits {
                    model.push(character);
                }
            }
            Keystroke::RemoveLast => {
                assert!(taken.is_ok());
                model.pop();
            }
            Keystroke::Clear => {
                assert!(taken.is_ok());
                model.clear();
            }
        }
        assert_eq!(line.as_str(), model);
        assert_eq!(line.characters(), model.chars().count());
    }
});
