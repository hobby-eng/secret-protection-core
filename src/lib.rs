//! Protection of secrets in memory and of the process that holds them.
//!
//! [`Secret`] is a buffer for secret bytes in whole memory pages of its own: where the system
//! allows it, they are locked in memory, so that they never reach swap, kept out of core dumps
//! and out of child processes, and wiped before they are given back. [`WorkArea`] is such pages for
//! the work of a computation that holds secrets, such as the memory of a password hash.
//! [`Isolation::enter`] applies, for good, what the system offers against a secret leaving the
//! process: no core dumps, no other program reading its memory, no new sockets and no file
//! changes. [`write_secret`] writes a secret to standard output without a copy of its own.
//!
//! Every type that holds secret bytes wipes them when dropped and shows none of them in its
//! `Debug` text. The crate makes the calls of each operating system in a module of its own; the
//! documentation of each item says, system by system, what it applies and what it does not cover.

mod os;
mod protect;

#[cfg(not(target_arch = "wasm32"))]
pub use protect::write_secret;
pub use protect::{Isolation, Secret, SecretError, WorkArea};
