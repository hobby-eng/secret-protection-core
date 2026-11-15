//! Public-fixture checks for the wasm32-unknown-unknown fallback.
use secret_protection_core::{
    ClosedSecret, Isolation, Options, Protection, Secret, SecretError, StackError,
    StackProperties, WorkArea, open_channels, run_on_protected_stack,
};

#[unsafe(no_mangle)]
pub extern "C" fn check_buffer() -> u32 {
    let mut secret = Secret::with_capacity(4);
    assert!(secret.push(b"abcd").is_ok());
    assert!(secret.push(b"x").is_err());
    secret.truncate(2);
    assert_eq!(secret.as_bytes(), b"ab");
    assert!(!secret.is_locked());
    assert!(matches!(Secret::locked(4), Err(SecretError::NotLocked)));
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn check_closed() -> u32 {
    let mut secret = ClosedSecret::with_capacity(4);
    assert!(secret.push(b"abcd").is_ok());
    assert!(secret.read(|b| b == b"abcd"));
    assert!(!secret.is_closed());
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn check_work_area() -> u32 {
    let Some(area) = WorkArea::new(16) else { return 0 };
    assert_eq!(area.as_slice(), &[0; 16]);
    assert!(!area.is_locked() && !area.is_out_of_dumps() && !area.is_out_of_children());
    assert!(WorkArea::new(usize::MAX).is_none());
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn check_strict() -> u32 {
    assert!(Isolation::enter_requiring(Options::new(), &[Protection::NoNewSockets]).is_err());
    assert!(open_channels().is_err());
    assert!(matches!(
        run_on_protected_stack(65536, StackProperties::default(), || 1),
        Err(StackError::Unsupported)
    ));
    1
}
