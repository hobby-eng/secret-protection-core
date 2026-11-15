//! What crosses between a worker, its parent and a window, as the fuzz targets under `fuzz/`
//! reach it. Built only with `--cfg fuzzing`, which cargo-fuzz sets.

use crate::{Isolation, Options};

/// The worker's reading of the setting its parent wrote.
pub fn setting(text: &str) -> Option<(u32, bool, &str)> {
    crate::worker::setting(text)
}

/// The options that `bits` name, as bits again.
pub fn options_again(bits: u32) -> u32 {
    Options::from_bits(bits).to_bits()
}

/// The parent's reading of its worker's report.
pub fn report(bytes: &[u8]) -> Option<Isolation> {
    Isolation::from_bytes(bytes)
}

/// The report a worker writes.
pub fn report_bytes(isolation: Isolation) -> Vec<u8> {
    isolation.to_bytes().to_vec()
}
