//! Typing a secret in a window without the window keeping it.
//!
//! An ordinary text field keeps copies in its toolkit's buffers, which nobody can wipe. So the
//! window sends each key to the worker as a [`Keystroke`] and keeps only the count for the dots,
//! and the worker builds the text in a [`SecretLine`].

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
    /// The bytes that carry it: a tag byte, then for a character its UTF-8 bytes. The array is
    /// wiped when the caller has sent it.
    pub fn to_bytes(self, out: &mut [u8; 5]) -> &[u8] {
        match self {
            Self::Char(character) => {
                out[0] = 1;
                let length = character.encode_utf8(&mut out[1..]).len();
                &out[..=length]
            }
            Self::RemoveLast => {
                out[0] = 2;
                &out[..1]
            }
            Self::Clear => {
                out[0] = 3;
                &out[..1]
            }
        }
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

    #[test]
    fn keystrokes_build_and_take_back_a_line() {
        let mut line = SecretLine::with_capacity(16);
        for character in "пароль1".chars() {
            let mut out = [0; 5];
            let bytes = Keystroke::Char(character).to_bytes(&mut out).to_vec();
            line.apply(Keystroke::from_bytes(&bytes).unwrap()).unwrap();
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
        assert_eq!(Keystroke::from_bytes(&[1, b'a', b'b']), None);
        assert_eq!(Keystroke::from_bytes(&[1]), None);
        assert_eq!(Keystroke::from_bytes(&[4]), None);
    }
}
