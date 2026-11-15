//! A GUI can forward individual keystrokes to a worker that holds the text in a [`SecretLine`].
//! The GUI sees each key event. Its toolkit and the application control any copies they retain.

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
}
