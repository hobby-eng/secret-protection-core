//! Memory buffers and process restrictions for applications that handle secrets.
//!
//! [`Secret`] and [`WorkArea`] report the protection granted to their allocations. [`Isolation`]
//! reports process and thread restrictions, and [`Worker`] runs operations in a separate process.
//! Platform guarantees and usage limits are described in `docs/TECHNICAL.md`.

mod channels;
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing;
mod input;
mod os;
mod protect;
mod stack;
mod worker;

pub use channels::{Channel, ChannelKind, OpenChannels, SharedMapping, open_channels};
pub use input::{Keystroke, KeystrokeBytes, SecretLine};
#[cfg(any(unix, windows))]
pub use input::{LineEnd, read_hidden_line};
#[cfg(unix)]
pub use protect::WritableFolder;
#[cfg(not(target_arch = "wasm32"))]
pub use protect::write_secret;
pub use protect::{
    ClosedSecret, Isolation, Measure, Missing, Options, Outcome, Protection, Reach, Secret,
    SecretError, WorkArea,
};
pub use stack::{
    CLEARED_STACK_BYTES, StackError, StackProperties, StackRun, clear_stack,
    run_on_protected_stack, with_cleared_stack,
};
pub use worker::{Worker, WorkerError, serve};
