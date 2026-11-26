//! What crosses between a worker, its parent and a window, as the fuzz targets under `fuzz/`
//! reach it. Built only with `--cfg fuzzing`, which cargo-fuzz sets. Each function runs the
//! crate's own reader on bytes from memory, as the program runs it on a pipe, a socket or a
//! terminal.

use std::io;

#[cfg(any(unix, windows))]
use crate::SecretLine;
use crate::{Isolation, Options, Secret};

/// The worker's reading of the setting its parent wrote.
pub fn setting(text: &str) -> Option<(u32, bool, &str)> {
    crate::worker::setting(text)
}

/// Whether `rest` names a worker's pipe and its nonce, as a Windows worker reads its setting.
pub fn windows_channel(terminal: bool, rest: Option<&str>) -> bool {
    crate::worker::windows_channel(terminal, rest)
}

/// How the name of a worker's pipe starts on Windows.
pub const PIPE_PREFIX: &str = crate::worker::PIPE_PREFIX;

/// The options that `bits` name, as bits again.
pub fn options_again(bits: u32) -> u32 {
    Options::from_bits(bits).to_bits()
}

/// Parses the isolation bytes in a startup report, excluding the separate clean-start flag.
pub fn report(bytes: &[u8]) -> Option<Isolation> {
    Isolation::from_bytes(bytes)
}

/// Encodes the isolation outcomes and their scope, the first part of a startup report.
pub fn report_bytes(isolation: Isolation) -> Vec<u8> {
    isolation.to_bytes().to_vec()
}

/// How long a whole startup report is: the isolation bytes and the clean-start flag.
pub const REPORT_BYTES: usize = crate::worker::REPORT_BYTES;

/// The parent's reading of a whole startup report: the isolation, and whether the start was
/// clean. `None` for bytes no worker sends, or of another length.
pub fn understood(bytes: &[u8]) -> Option<(Isolation, bool)> {
    crate::worker::understood(bytes.try_into().ok()?)
}

/// The requests a worker takes from `input`, each answered with its bytes reversed, and what it
/// writes back.
pub fn requests(input: &[u8], most: usize) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut stream = Stream {
        input,
        written: Vec::new(),
    };
    let mut taken = Vec::new();
    crate::worker::requests(&mut stream, most, |request| {
        taken.push(request.to_vec());
        let reversed: Vec<u8> = request.iter().rev().copied().collect();
        let mut reply = Secret::with_capacity(request.len());
        reply.push(&reversed).ok();
        reply
    });
    (taken, stream.written)
}

/// The parent's reading of an answer from `input`.
pub fn answer(input: &[u8], most: usize) -> io::Result<Vec<u8>> {
    let mut rest = input;
    crate::worker::read_answer(|buffer| io::Read::read_exact(&mut rest, buffer), most)
        .map(|answer| answer.as_bytes().to_vec())
}

/// The list of thread IDs a Windows worker reads from its parent during its census.
pub fn roster(input: &[u8], most: usize) -> io::Result<Option<Vec<u32>>> {
    crate::worker::read_roster(&mut &input[..], most)
}

/// What `read_hidden_line` makes of `input` on a Unix terminal, which sends UTF-8: how the line
/// ended, and the line. Where there is a terminal to read: Unix and Windows.
#[cfg(any(unix, windows))]
pub fn edit_utf8(input: &[u8], capacity: usize) -> (io::Result<crate::LineEnd>, String) {
    let mut rest = input;
    edit(capacity, || {
        crate::input::utf8_char(|byte| {
            let Some((&first, after)) = rest.split_first() else {
                return Ok(false);
            };
            *byte = first;
            rest = after;
            Ok(true)
        })
    })
}

/// As [`edit_utf8`] for the Windows console, which sends UTF-16.
#[cfg(any(unix, windows))]
pub fn edit_utf16(input: &[u16], capacity: usize) -> (io::Result<crate::LineEnd>, String) {
    let mut rest = input;
    edit(capacity, || {
        crate::input::utf16_char(|unit| {
            let Some((&first, after)) = rest.split_first() else {
                return Ok(false);
            };
            *unit = first;
            rest = after;
            Ok(true)
        })
    })
}

#[cfg(any(unix, windows))]
fn edit(
    capacity: usize,
    next: impl FnMut() -> io::Result<Option<char>>,
) -> (io::Result<crate::LineEnd>, String) {
    let mut line = SecretLine::with_capacity(capacity);
    let ended = crate::input::edit(&mut line, next);
    (ended, line.as_str().to_owned())
}

/// A worker's channel in memory: it reads `input` and keeps what is written.
struct Stream<'a> {
    input: &'a [u8],
    written: Vec<u8>,
}

impl io::Read for Stream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.input.read(buffer)
    }
}

impl io::Write for Stream<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
