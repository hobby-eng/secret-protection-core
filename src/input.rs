//! A GUI can forward individual keystrokes to a worker that holds the text in a [`SecretLine`].
//! The GUI sees each key event. Its toolkit and the application control any copies they retain.
//! On a terminal, [`read_hidden_line`] reads the keys into a line without showing them.

#[cfg(any(unix, windows))]
use std::io;

use zeroize::Zeroize;

use crate::protect::{Secret, SecretError};

/// What a window sends for one key of a secret field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Keystroke {
    /// A character typed.
    Char(char),
    /// The last character taken back (Backspace).
    RemoveLast,
    /// Every character taken back.
    Clear,
}

impl Keystroke {
    /// The bytes that carry it to the worker: a tag byte, then for a character its UTF-8 bytes.
    /// They come in a value that wipes itself when dropped.
    pub fn to_bytes(self) -> KeystrokeBytes {
        let mut bytes = [0; 5];
        let length = match self {
            Self::Char(character) => {
                bytes[0] = 1;
                1 + character.encode_utf8(&mut bytes[1..]).len()
            }
            Self::RemoveLast => {
                bytes[0] = 2;
                1
            }
            Self::Clear => {
                bytes[0] = 3;
                1
            }
        };
        KeystrokeBytes { bytes, length }
    }

    /// The keystroke that [`Keystroke::to_bytes`] made, or `None` for any other bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [1, rest @ ..] => {
                let text = std::str::from_utf8(rest).ok()?;
                let mut characters = text.chars();
                let character = characters.next()?;
                characters.next().is_none().then_some(Self::Char(character))
            }
            [2] => Some(Self::RemoveLast),
            [3] => Some(Self::Clear),
            _ => None,
        }
    }
}

/// The bytes of one [`Keystroke`], wiped when dropped. Drop it as soon as it is sent; the
/// `Keystroke` itself is a plain value that nothing wipes, so keep none around either.
pub struct KeystrokeBytes {
    bytes: [u8; 5],
    length: usize,
}

impl KeystrokeBytes {
    /// The bytes to send.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

impl Drop for KeystrokeBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for KeystrokeBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeystrokeBytes(hidden)")
    }
}

impl std::fmt::Debug for Keystroke {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Char(_) => "Keystroke::Char(hidden)",
            Self::RemoveLast => "Keystroke::RemoveLast",
            Self::Clear => "Keystroke::Clear",
        })
    }
}

/// A line of secret text collected one character at a time, in a [`Secret`] of a fixed capacity
/// in bytes: what a worker keeps of a password typed in a window.
pub struct SecretLine {
    secret: Secret,
    characters: usize,
}

impl SecretLine {
    /// An empty line that holds up to `bytes` bytes of UTF-8.
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            secret: Secret::with_capacity(bytes),
            characters: 0,
        }
    }

    /// Applies one keystroke; a character that does not fit is refused with [`SecretError::Full`]
    /// and changes nothing.
    pub fn apply(&mut self, keystroke: Keystroke) -> Result<(), SecretError> {
        match keystroke {
            Keystroke::Char(character) => self.push(character),
            Keystroke::RemoveLast => {
                self.remove_last();
                Ok(())
            }
            Keystroke::Clear => {
                self.clear();
                Ok(())
            }
        }
    }

    /// Appends a character.
    pub fn push(&mut self, character: char) -> Result<(), SecretError> {
        let mut bytes = [0; 4];
        let pushed = self
            .secret
            .push(character.encode_utf8(&mut bytes).as_bytes());
        bytes.zeroize();
        pushed?;
        self.characters += 1;
        Ok(())
    }

    /// Takes back the last character and wipes its bytes; on an empty line, nothing.
    pub fn remove_last(&mut self) {
        let bytes = self.secret.as_bytes();
        // The last character starts at the last byte that is not a continuation byte.
        if let Some(start) = bytes.iter().rposition(|&byte| byte & 0xC0 != 0x80) {
            self.secret.truncate(start);
            self.characters -= 1;
        }
    }

    /// Takes back every character and wipes their bytes.
    pub fn clear(&mut self) {
        self.secret.truncate(0);
        self.characters = 0;
    }

    /// How many characters it holds: all a window needs, to draw dots.
    pub fn characters(&self) -> usize {
        self.characters
    }

    /// The text, in protected pages.
    pub fn as_secret(&self) -> &Secret {
        &self.secret
    }

    /// The text as a string; every push was a whole character, so it is always UTF-8.
    pub fn as_str(&self) -> &str {
        self.secret.as_str().unwrap_or_default()
    }
}

impl std::fmt::Debug for SecretLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretLine({} characters, hidden)", self.characters)
    }
}

/// How a hidden line ended.
#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineEnd {
    /// Enter took the line.
    Entered,
    /// The input ended: Ctrl+D or Ctrl+Z on an empty line, or the terminal closed.
    EndOfInput,
    /// Ctrl+C cancelled the line.
    Cancelled,
}

/// Reads a line typed on the terminal into `line` and shows none of it. The terminal's echo, line
/// editing and signal keys are off while it reads, on Unix also flow control and the settings that
/// would drop Enter or a byte's eighth bit, as the terminal reports back, and restored after; a
/// failed restore is an error, and a Unix input set not to wait is refused. The line is emptied
/// first, and again unless Enter took it. Keys, errors and which terminal: docs/API.md.
#[cfg(any(unix, windows))]
pub fn read_hidden_line(prompt: &str, line: &mut SecretLine) -> io::Result<LineEnd> {
    // One reading at a time: a second would take the first's hidden settings for the ones to
    // restore.
    static READING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _reading = READING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    line.clear();
    // Each character passes through the stack on its way into the line: wiped after.
    let ended = crate::stack::with_cleared::<READING_STACK_BYTES, _>(|| {
        let mut terminal = crate::os::HiddenTerminal::open()?;
        let edited = terminal
            .write(prompt)
            .and_then(|()| edit(line, || terminal.next_char()));
        // Back first, so that output that cannot drain keeps no key hidden; a terminal left
        // changed is the error that counts most, and is returned before anything is written.
        let restored = terminal.restore();
        // The Enter typed was not shown: what comes next starts a line of its own. The line
        // counts whether or not this lands.
        if restored.is_ok() {
            let _ = terminal.write("\r\n");
        }
        restored.and(edited)
    });
    if !matches!(ended, Ok(LineEnd::Entered)) {
        line.clear();
    }
    ended
}

/// The stack below its frame that [`read_hidden_line`] wipes after the reading, which stays far
/// shallower; a thread needs that much free.
#[cfg(any(unix, windows))]
const READING_STACK_BYTES: usize = 16 << 10;

/// How far an escape sequence, as an arrow, function or mouse key sends it, has come.
#[cfg(any(unix, windows))]
#[derive(Clone, Copy)]
enum Sequence {
    Outside,
    /// After ESC.
    Escape,
    /// After ESC [, until a final byte; `parameters` once one came.
    Control {
        parameters: bool,
    },
    /// After ESC [ [, as the Linux console sends F1 to F5: one key more.
    Console,
    /// After ESC O, through its parameters to a final byte.
    Shift,
    /// The bytes still to come of a mouse report, after ESC [ M.
    Mouse(u8),
}

#[cfg(any(unix, windows))]
impl Sequence {
    /// The state after `key`, and the key to act on: `None` when it belongs to a sequence. A
    /// control key ends any sequence and counts, so that Enter is never swallowed; DEL and the C1
    /// controls are part of a mouse report, whose bytes are all 0x20 and above.
    fn step(self, key: char) -> (Self, Option<char>) {
        use Sequence as S;
        let parameter = |low| (low..='\u{3f}').contains(&key);
        match self {
            S::Outside => (S::Outside, Some(key)),
            // A mouse report's bytes are 0x20 and above, DEL (column or row 95) among them; a key
            // below ends it and counts.
            S::Mouse(left) if key >= ' ' => (
                if left > 1 {
                    S::Mouse(left - 1)
                } else {
                    S::Outside
                },
                None,
            ),
            _ if key.is_control() => (S::Outside, Some(key)),
            S::Escape => match key {
                '[' => (S::Control { parameters: false }, None),
                'O' => (S::Shift, None),
                // After an Escape alone, as the Escape key sends it, a key counts as itself.
                _ => (S::Outside, Some(key)),
            },
            S::Control { parameters: false } if key == '[' => (S::Console, None),
            S::Control { parameters: false } if key == 'M' => (S::Mouse(3), None),
            S::Control { .. } if parameter('\u{20}') => (S::Control { parameters: true }, None),
            S::Control { .. } if ('\u{40}'..='\u{7e}').contains(&key) => (S::Outside, None),
            S::Control { .. } => (S::Outside, Some(key)),
            // Enter on the keypad, in the terminal's application mode.
            S::Shift if key == 'M' => (S::Outside, Some('\r')),
            S::Shift if parameter('\u{30}') => (S::Shift, None),
            S::Console | S::Shift => (S::Outside, None),
            S::Mouse(_) => (S::Outside, Some(key)),
        }
    }
}

/// Edits `line` with the keys that `next` reads, until Enter, Ctrl+C or the end of the input.
/// Escape sequences and the control keys it has no use for are dropped. Keys typed once the line
/// is full are counted: Backspace takes them back first, and a line is taken only when it fits
/// whole.
#[cfg(any(unix, windows))]
pub(crate) fn edit(
    line: &mut SecretLine,
    mut next: impl FnMut() -> io::Result<Option<char>>,
) -> io::Result<LineEnd> {
    let mut sequence = Sequence::Outside;
    let mut over = 0_usize;
    while let Some(typed) = next()? {
        let (after, key) = sequence.step(typed);
        sequence = after;
        match key {
            None => {}
            Some('\r' | '\n') if over == 0 => return Ok(LineEnd::Entered),
            Some('\r' | '\n') => return Err(too_long()),
            Some('\u{7f}' | '\u{8}') if over > 0 => over -= 1,
            Some('\u{7f}' | '\u{8}') => line.remove_last(),
            Some('\u{15}') => {
                line.clear();
                over = 0;
            }
            Some('\u{3}') => return Ok(LineEnd::Cancelled),
            Some('\u{4}' | '\u{1a}') if line.characters() == 0 && over == 0 => {
                return Ok(LineEnd::EndOfInput);
            }
            Some('\u{1b}') => sequence = Sequence::Escape,
            Some(key) if key.is_control() => {}
            Some(_) if over > 0 => over = one_more(over)?,
            // A key that does not fit stays out, and so does every key after it.
            Some(key) => over += usize::from(line.push(key).is_err()),
        }
    }
    Ok(LineEnd::EndOfInput)
}

/// One more key past a full line. A count that would leave the range of `usize`, which takes
/// four billion keys on a 32-bit system, refuses the line rather than wrap or panic.
#[cfg(any(unix, windows))]
fn one_more(over: usize) -> io::Result<usize> {
    over.checked_add(1).ok_or_else(too_long)
}

#[cfg(any(unix, windows))]
fn too_long() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "the line is longer than allowed",
    )
}

/// The next character of UTF-8 input, whose bytes `read_byte` puts one at a time into a buffer
/// that is wiped when the character is whole; `false` from it is the end of the input. `None` at
/// the end, an error for bytes that are no UTF-8 or end inside a character.
#[cfg(any(unix, all(fuzzing, windows)))]
pub(crate) fn utf8_char(
    mut read_byte: impl FnMut(&mut u8) -> io::Result<bool>,
) -> io::Result<Option<char>> {
    let mut bytes = zeroize::Zeroizing::new([0u8; 4]);
    let mut length = 0;
    loop {
        match read_byte(&mut bytes[length])? {
            true => length += 1,
            false if length == 0 => return Ok(None),
            false => return Err(not_utf8()),
        }
        match std::str::from_utf8(&bytes[..length]) {
            Ok(text) => return Ok(text.chars().next()),
            Err(error) if error.error_len().is_none() && length < bytes.len() => {}
            Err(_) => return Err(not_utf8()),
        }
    }
}

/// The next character of UTF-16 input, as the Windows console gives it, one unit at a time into
/// a buffer that is wiped; a character beyond the first 65,536 takes two. `None` at the end.
#[cfg(any(windows, all(any(fuzzing, test), unix)))]
pub(crate) fn utf16_char(
    mut read_unit: impl FnMut(&mut u16) -> io::Result<bool>,
) -> io::Result<Option<char>> {
    let mut units = zeroize::Zeroizing::new([0_u16; 2]);
    if !read_unit(&mut units[0])? {
        return Ok(None);
    }
    let length = if (0xD800..0xDC00).contains(&units[0]) {
        if !read_unit(&mut units[1])? {
            return Err(not_utf16());
        }
        2
    } else {
        1
    };
    match char::decode_utf16(units[..length].iter().copied()).next() {
        Some(Ok(character)) => Ok(Some(character)),
        _ => Err(not_utf16()),
    }
}

#[cfg(any(unix, all(fuzzing, windows)))]
fn not_utf8() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the terminal sent bytes that are not UTF-8",
    )
}

#[cfg(any(windows, all(any(fuzzing, test), unix)))]
fn not_utf16() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the console sent UTF-16 that is no text",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each keystroke crosses as bytes and comes back as itself; other bytes are no keystroke,
    /// and the debug text of a character hides it.
    #[test]
    fn keystrokes_cross_as_bytes_and_hide_their_character() {
        for keystroke in [
            Keystroke::Char('ж'),
            Keystroke::RemoveLast,
            Keystroke::Clear,
        ] {
            assert_eq!(
                Keystroke::from_bytes(keystroke.to_bytes().as_bytes()),
                Some(keystroke)
            );
        }
        for other in [&[][..], &[1], &[1, 0xFF], &[1, b'a', b'b'], &[2, 0], &[4]] {
            assert_eq!(Keystroke::from_bytes(other), None, "{other:?}");
        }
        assert_eq!(
            format!("{:?}", Keystroke::Char('ж')),
            "Keystroke::Char(hidden)"
        );
        assert_eq!(format!("{:?}", Keystroke::Clear), "Keystroke::Clear");
        assert_eq!(
            format!("{:?}", Keystroke::RemoveLast),
            "Keystroke::RemoveLast"
        );
    }

    #[test]
    fn keystrokes_build_and_take_back_a_line() {
        let mut line = SecretLine::with_capacity(16);
        for character in "пароль1".chars() {
            let bytes = Keystroke::Char(character).to_bytes();
            line.apply(Keystroke::from_bytes(bytes.as_bytes()).unwrap())
                .unwrap();
        }
        assert_eq!((line.as_str(), line.characters()), ("пароль1", 7));
        line.apply(Keystroke::RemoveLast).unwrap();
        line.apply(Keystroke::RemoveLast).unwrap();
        assert_eq!((line.as_str(), line.characters()), ("парол", 5));
        // The bytes cut are gone, and wiped.
        assert_eq!(line.as_secret().as_bytes().len(), 10);
        assert_eq!(line.push('щ'), Ok(()));
        assert_eq!(line.push('é'), Ok(()));
        assert_eq!(line.push('x'), Ok(()));
        assert_eq!(line.push('ж'), Err(SecretError::Full { capacity: 16 }));
        assert_eq!(line.as_str(), "паролщéx");
        line.apply(Keystroke::Clear).unwrap();
        assert_eq!((line.as_str(), line.characters()), ("", 0));
        line.remove_last();
        assert_eq!(line.characters(), 0);
        assert_eq!(format!("{line:?}"), "SecretLine(0 characters, hidden)");
        line.push('ж').unwrap();
        assert_eq!(format!("{line:?}"), "SecretLine(1 characters, hidden)");
        assert_eq!(
            format!("{:?}", Keystroke::Char('a')),
            "Keystroke::Char(hidden)"
        );
        // Each keystroke carries only its own bytes, whatever was sent before it.
        assert_eq!(Keystroke::Char('€').to_bytes().as_bytes().len(), 4);
        assert_eq!(Keystroke::Char('a').to_bytes().as_bytes(), [1, b'a']);
        assert_eq!(Keystroke::RemoveLast.to_bytes().as_bytes(), [2]);
        assert_eq!(Keystroke::Clear.to_bytes().as_bytes(), [3]);
        assert_eq!(
            format!("{:?}", Keystroke::Char('a').to_bytes()),
            "KeystrokeBytes(hidden)"
        );
        assert_eq!(Keystroke::from_bytes(&[1, b'a', b'b']), None);
        assert_eq!(Keystroke::from_bytes(&[1]), None);
        assert_eq!(Keystroke::from_bytes(&[4]), None);
    }

    /// How typing `keys` into a line of `capacity` bytes ended, and the line it left.
    #[cfg(any(unix, windows))]
    fn typed(keys: &str, capacity: usize) -> (Result<LineEnd, std::io::ErrorKind>, String) {
        let mut line = SecretLine::with_capacity(capacity);
        let mut keys = keys.chars();
        let ended = edit(&mut line, || Ok(keys.next())).map_err(|error| error.kind());
        (ended, line.as_str().to_owned())
    }

    /// Enter takes the line; Backspace and Ctrl+U edit it; the keys that send escape sequences
    /// leave nothing, and neither does any other control key.
    #[cfg(any(unix, windows))]
    #[test]
    fn keys_edit_a_line_until_enter() {
        let taken = |line: &str| (Ok(LineEnd::Entered), line.to_owned());
        assert_eq!(typed("pass\r", 64), taken("pass"));
        assert_eq!(typed("pass\n", 64), taken("pass"));
        assert_eq!(typed("pas\u{7f}ss\u{8}t\r", 64), taken("past"));
        assert_eq!(typed("old\u{15}new\r", 64), taken("new"));
        // An arrow, a modified arrow, F1 and F5.
        assert_eq!(
            typed("a\x1b[Ab\x1b[1;5Cc\x1bOPd\x1b[15~e\r", 64),
            taken("abcde")
        );
        // F1 with a modifier as SS3 with parameters, F1 on the Linux console, a mouse report.
        assert_eq!(
            typed("a\x1bO2Pb\x1bO1;5Pc\x1b[[Ad\x1b[M !!e\r", 64),
            taken("abcde")
        );
        // Enter on the keypad in application mode.
        assert_eq!(typed("abc\x1bOM", 64), taken("abc"));
        // A key after an Escape alone counts; Enter ends a sequence left unfinished.
        assert_eq!(typed("\x1bx\r", 64), taken("x"));
        assert_eq!(typed("ab\x1b[1\r", 64), taken("ab"));
        assert_eq!(typed("\x1bO\r", 64), taken(""));
        assert_eq!(typed("a\x1b[M\rb", 64), taken("a"));
        // A mouse report at column 95 holds DEL, which is no Backspace there.
        assert_eq!(typed("a\x1b[M \x7f!b\r", 64), taken("ab"));
        // SGR mouse reports, a press and a release, at a column and row past 223.
        assert_eq!(
            typed("a\x1b[<0;300;240Mb\x1b[<0;300;240mc\r", 64),
            taken("abc")
        );
        // Tab, Ctrl+W, NUL and a C1 control.
        assert_eq!(typed("a\tb\u{17}c\u{0}d\u{85}e\r", 64), taken("abcde"));
        assert_eq!(typed("пароль é\r", 64), taken("пароль é"));
    }

    /// Ctrl+C cancels; Ctrl+D or Ctrl+Z on an empty line, or no more keys, end the input; on a
    /// line with text, Ctrl+D and Ctrl+Z are dropped.
    #[cfg(any(unix, windows))]
    #[test]
    fn keys_cancel_or_end_the_input() {
        let ended = |line: &str| (Ok(LineEnd::EndOfInput), line.to_owned());
        assert_eq!(typed("ab\u{3}cd\r", 64).0, Ok(LineEnd::Cancelled));
        assert_eq!(typed("\u{4}", 64), ended(""));
        assert_eq!(typed("\u{1a}", 64), ended(""));
        assert_eq!(typed("ab", 64), ended("ab"));
        assert_eq!(
            typed("a\u{4}b\u{1a}c\r", 64),
            (Ok(LineEnd::Entered), "abc".to_owned())
        );
        assert_eq!(typed("ab\u{15}\u{4}", 64), ended(""));
    }

    /// Keys typed once the line is full stay out of it and are counted: the line is refused at
    /// Enter unless Backspace or Ctrl+U took them back.
    #[cfg(any(unix, windows))]
    #[test]
    fn a_line_too_long_is_refused_whole() {
        let refused = Err(std::io::ErrorKind::InvalidInput);
        let taken = |line: &str| (Ok(LineEnd::Entered), line.to_owned());
        assert_eq!(typed("abcdef\r", 4).0, refused);
        assert_eq!(typed("abcdef\u{7f}\u{7f}\r", 4), taken("abcd"));
        assert_eq!(typed("abcdef\u{7f}\u{7f}\u{7f}\r", 4), taken("abc"));
        assert_eq!(typed("abcdef\u{15}xy\r", 4), taken("xy"));
        // A wide character that does not fit keeps every later key out, even one that would fit.
        assert_eq!(typed("abcd€e\r", 5).0, refused);
        assert_eq!(typed("abcd€e\u{7f}\u{7f}\r", 5), taken("abcd"));
        // Ctrl+D ends nothing while keys are kept out.
        assert_eq!(typed("x\u{4}\r", 0).0, refused);
    }

    /// A failed read ends the editing with its error.
    #[cfg(any(unix, windows))]
    #[test]
    fn a_failed_read_ends_the_editing() {
        let mut line = SecretLine::with_capacity(8);
        let failed = edit(&mut line, || Err(std::io::Error::other("gone")));
        assert_eq!(
            failed.map_err(|error| error.to_string()),
            Err("gone".to_owned())
        );
    }

    /// Bytes become characters one whole character at a time; bytes that are no UTF-8, or end
    /// inside a character, are an error.
    #[cfg(unix)]
    #[test]
    fn utf8_input_becomes_characters() {
        fn chars(input: &[u8]) -> io::Result<String> {
            let mut rest = input;
            let mut text = String::new();
            while let Some(character) = utf8_char(|byte| {
                let Some((&first, after)) = rest.split_first() else {
                    return Ok(false);
                };
                *byte = first;
                rest = after;
                Ok(true)
            })? {
                text.push(character);
            }
            Ok(text)
        }
        assert_eq!(chars("aé🔍".as_bytes()).unwrap(), "aé🔍");
        for bad in [&[0xff][..], &[0xe2, 0x82], &[0xc3, 0x28]] {
            assert_eq!(
                chars(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{bad:?}"
            );
        }
    }

    /// Units become characters, a pair of surrogates one; a lone surrogate is an error.
    #[cfg(any(unix, windows))]
    #[test]
    fn utf16_input_becomes_characters() {
        fn chars(input: &[u16]) -> io::Result<String> {
            let mut rest = input;
            let mut text = String::new();
            while let Some(character) = utf16_char(|unit| {
                let Some((&first, after)) = rest.split_first() else {
                    return Ok(false);
                };
                *unit = first;
                rest = after;
                Ok(true)
            })? {
                text.push(character);
            }
            Ok(text)
        }
        assert_eq!(chars(&[0x61, 0xD83D, 0xDD0D]).unwrap(), "a🔍");
        for bad in [&[0xD83D][..], &[0xDC00], &[0xD83D, 0x61]] {
            assert_eq!(
                chars(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{bad:?}"
            );
        }
    }

    /// The count of keys past a full line refuses the line where it would leave its range.
    #[cfg(any(unix, windows))]
    #[test]
    fn the_count_past_a_full_line_stays_bounded() {
        assert_eq!(one_more(1).unwrap(), 2);
        assert_eq!(
            one_more(usize::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
