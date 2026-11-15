//! Keeps secrets out of swap, core dumps, child processes and the reach of other programs.
//!
//! [`Secret`] and [`WorkArea`] give memory for secrets, [`Isolation`] closes the process against a
//! secret leaving it, and [`Worker`] runs the secret work in a separate isolated process. What each
//! system does is described in docs/TECHNICAL.md.

mod channels;
mod input;
mod os;
mod protect;
mod stack;
mod worker;

pub use channels::{Channel, ChannelKind, open_channels};
pub use input::{Keystroke, SecretLine};
#[cfg(not(target_arch = "wasm32"))]
pub use protect::write_secret;
pub use protect::{
    ClosedSecret, Isolation, Measure, Missing, Options, Protection, Reach, Secret, SecretError,
    WorkArea,
};
pub use stack::{StackRun, run_on_protected_stack};
pub use worker::{Worker, WorkerError, serve};
