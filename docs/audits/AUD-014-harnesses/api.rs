//! Check public inputs using the standard library's Unicode scalar values.
use secret_protection_core::{Keystroke, Secret, SecretError, SecretLine};

fn main() {
    let mut line = SecretLine::with_capacity(4);
    let mut count = 0u32;
    for c in (0..=0x10ffff).filter_map(char::from_u32) {
        let frame = Keystroke::Char(c).to_bytes();
        let bytes = frame.as_bytes();
        let mut encoded = [0; 4];
        let text = c.encode_utf8(&mut encoded);
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..], text.as_bytes());
        let key = Keystroke::from_bytes(bytes).expect("valid encoded scalar");
        line.apply(key).expect("one scalar fits");
        assert_eq!(line.as_str(), text);
        assert_eq!(line.characters(), 1);
        line.remove_last();
        assert_eq!(line.as_str(), "");
        count += 1;
    }
    assert_eq!(count, 1_112_064);
    for invalid in [
        &[][..],
        &[0],
        &[1],
        &[1, 0xff],
        &[1, 97, 98],
        &[2, 0],
        &[3, 0],
    ] {
        assert!(Keystroke::from_bytes(invalid).is_none());
    }
    let mut public = Secret::with_capacity(2);
    public.push(b"ok").expect("two bytes fit");
    assert!(matches!(
        public.push(b"!"),
        Err(SecretError::Full { capacity: 2 })
    ));
    assert_eq!(public.as_bytes(), b"ok");
    println!("{count} Unicode scalars, 7 invalid frames and one capacity boundary passed");
}
