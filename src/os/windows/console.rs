//! The console of a hidden line on Windows: its echo, its own line editing and Ctrl+C as a signal
//! off, checked by reading the mode back, and the mode it had restored after. Only the standard
//! handles are used; a worker has no console, so its parent reads the line. Ctrl+Break stays a
//! signal, whose default handler ends the program before the mode comes back.
#![allow(
    unsafe_code,
    reason = "the console calls of Windows are foreign functions"
)]

use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    FlushConsoleInputBuffer, GetConsoleMode, GetStdHandle, ReadConsoleW, STD_ERROR_HANDLE,
    STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode, WriteConsoleW,
};
use zeroize::Zeroizing;

/// What a hidden line switches off: echo, the console's own line editing, and Ctrl+C as a
/// signal, so that every way out of the reading restores the mode.
const SWITCHED_OFF: CONSOLE_MODE = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;

/// A console that shows nothing typed on it until [`HiddenTerminal::restore`] or the drop.
pub(crate) struct HiddenTerminal {
    input: HANDLE,
    /// Where the prompt may go: standard error, then standard output, those that are consoles.
    /// One that refuses the write, as a handle opened for reading does, is passed over.
    outputs: Vec<HANDLE>,
    original: CONSOLE_MODE,
    restored: bool,
    /// Whether the switch read back, after which input is dropped on the way out too.
    switched: bool,
}

impl HiddenTerminal {
    /// The console of standard input, switched, and refused unless the switch reads back.
    pub(crate) fn open() -> io::Result<Self> {
        let input = standard(STD_INPUT_HANDLE);
        let original = mode(input).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "standard input is no console")
        })?;
        // SAFETY: the console input handle of this process, and a mode.
        if unsafe { SetConsoleMode(input, original & !SWITCHED_OFF) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut console = Self {
            input,
            outputs: [STD_ERROR_HANDLE, STD_OUTPUT_HANDLE]
                .into_iter()
                .map(standard)
                .filter(|&handle| mode(handle).is_some())
                .collect(),
            original,
            restored: false,
            switched: false,
        };
        if mode(input).is_none_or(|now| now & SWITCHED_OFF != 0) {
            return Err(io::Error::other(
                "the console did not turn its echo off; nothing was read",
            ));
        }
        console.switched = true;
        // The keys waiting now, which the console may have shown, or that another program put
        // in, are no part of the line: a console that cannot drop them is refused.
        // SAFETY: the console input handle of this process.
        if unsafe { FlushConsoleInputBuffer(input) } == 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("the input waiting before the reading could not be dropped: {error}"),
            ));
        }
        Ok(console)
    }

    /// Writes `text` to the console, if one shows it.
    pub(crate) fn write(&mut self, text: &str) -> io::Result<()> {
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
        let wide: Vec<u16> = text.encode_utf16().collect();
        while let Some(&output) = self.outputs.first() {
            match write_wide(output, &wide) {
                Err(error) if error.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok() => {
                    self.outputs.remove(0);
                }
                written => return written,
            }
        }
        Ok(())
    }

    /// The next character typed, or `None` when the console gives no more. A character beyond
    /// the first 65,536 comes as two UTF-16 units, read into a buffer that is wiped.
    pub(crate) fn next_char(&mut self) -> io::Result<Option<char>> {
        let mut units = Zeroizing::new([0_u16; 2]);
        if !self.read_unit(&mut units[0])? {
            return Ok(None);
        }
        let length = if (0xD800..0xDC00).contains(&units[0]) {
            if !self.read_unit(&mut units[1])? {
                return Err(not_text());
            }
            2
        } else {
            1
        };
        match char::decode_utf16(units[..length].iter().copied()).next() {
            Some(Ok(character)) => Ok(Some(character)),
            _ => Err(not_text()),
        }
    }

    /// Reads one UTF-16 unit into `unit`; `false` when the console gave none.
    fn read_unit(&mut self, unit: &mut u16) -> io::Result<bool> {
        let mut read = 0;
        // SAFETY: ReadConsoleW writes at most one unit, into `unit`, which lives for the call.
        let done = unsafe {
            ReadConsoleW(
                self.input,
                ptr::from_mut(unit).cast(),
                1,
                &mut read,
                ptr::null(),
            )
        };
        if done == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(read == 1)
    }
}

impl HiddenTerminal {
    /// Puts back the mode it found, once. What was typed after Enter, such as the rest of a pasted
    /// text, goes before the console echoes again.
    pub(crate) fn restore(&mut self) -> io::Result<()> {
        if std::mem::replace(&mut self.restored, true) {
            return Ok(());
        }
        // SAFETY: the console input handle of this process.
        let flushed = !self.switched || unsafe { FlushConsoleInputBuffer(self.input) } != 0;
        // SAFETY: as above, and the mode read before the switch.
        if unsafe { SetConsoleMode(self.input, self.original) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if mode(self.input) != Some(self.original) {
            return Err(io::Error::other("the console did not take back its mode"));
        }
        if !flushed {
            return Err(io::Error::other(
                "the input left after the reading could not be dropped",
            ));
        }
        Ok(())
    }
}

impl Drop for HiddenTerminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// A standard handle of this process, which it keeps open; a missing one is no console.
fn standard(which: STD_HANDLE) -> HANDLE {
    // SAFETY: GetStdHandle takes an integer and returns a handle or an invalid one.
    unsafe { GetStdHandle(which) }
}

/// The mode of the console behind `handle`, or `None` when it is no console.
fn mode(handle: HANDLE) -> Option<CONSOLE_MODE> {
    let mut mode = 0;
    // SAFETY: writes the mode into `mode`, and fails when the handle is no console.
    (unsafe { GetConsoleMode(handle, &mut mode) } != 0).then_some(mode)
}

fn not_text() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the console sent UTF-16 that is no text",
    )
}

/// Writes `wide` whole to the console `output`, again for what a partial write left.
fn write_wide(output: HANDLE, wide: &[u16]) -> io::Result<()> {
    let mut rest = wide;
    while !rest.is_empty() {
        let length = u32::try_from(rest.len()).unwrap_or(u32::MAX);
        let mut written = 0;
        // SAFETY: WriteConsoleW reads `length` units of `rest`, which live for the call.
        if unsafe { WriteConsoleW(output, rest.as_ptr(), length, &mut written, ptr::null()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        match usize::try_from(written) {
            Ok(0) | Err(_) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => rest = rest.get(written..).unwrap_or_default(),
        }
    }
    Ok(())
}
