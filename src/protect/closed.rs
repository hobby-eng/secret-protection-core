//! [`ClosedSecret`]: a secret whose pages refuse every access between uses.

use std::fmt;

use super::{Secret, SecretError};
use crate::os::{Access, Region};

/// Like [`Secret`], but its pages refuse all access between uses. The bytes are reachable only
/// inside [`ClosedSecret::read`] and [`ClosedSecret::write`], so a stray read elsewhere in the
/// program (a Heartbleed-style bug) crashes instead of leaking. Each use costs two system calls.
pub struct ClosedSecret {
    secret: Secret,
    /// What the pages allow now, as the system last confirmed.
    access: Access,
}

impl ClosedSecret {
    /// An empty buffer that holds up to `bytes` bytes, as [`Secret::with_capacity`], closed.
    pub fn with_capacity(bytes: usize) -> Self {
        Self::closing(Secret::with_capacity(bytes))
    }

    /// As [`Secret::locked`]: refuses with [`SecretError::NotLocked`] when the system does not lock
    /// the pages.
    pub fn locked(bytes: usize) -> Result<Self, SecretError> {
        Secret::locked(bytes).map(Self::closing)
    }

    fn closing(secret: Secret) -> Self {
        // New pages allow reading and writing until the system agrees to close them.
        let access = after(
            Access::ReadWrite,
            Access::Nothing,
            secret.pages.region().allow(Access::Nothing),
        );
        Self { secret, access }
    }

    /// Appends `bytes`, as [`Secret::push`].
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), SecretError> {
        let _open = Open::new(
            self.secret.pages.region(),
            Access::ReadWrite,
            &mut self.access,
        );
        self.secret.push(bytes)
    }

    /// Shortens the contents to `len` bytes and wipes what it cuts, as [`Secret::truncate`].
    pub fn truncate(&mut self, len: usize) {
        let _open = Open::new(
            self.secret.pages.region(),
            Access::ReadWrite,
            &mut self.access,
        );
        self.secret.truncate(len);
    }

    /// Opens the pages for reading, hands the bytes pushed so far to `use_bytes`, and closes them
    /// again.
    pub fn read<R>(&mut self, use_bytes: impl FnOnce(&[u8]) -> R) -> R {
        let _open = Open::new(self.secret.pages.region(), Access::Read, &mut self.access);
        use_bytes(self.secret.as_bytes())
    }

    /// Opens the pages for reading and writing, hands the bytes pushed so far to `change`, and
    /// closes them again.
    pub fn write<R>(&mut self, change: impl FnOnce(&mut [u8]) -> R) -> R {
        let _open = Open::new(
            self.secret.pages.region(),
            Access::ReadWrite,
            &mut self.access,
        );
        change(self.secret.as_mut_bytes())
    }

    /// How many bytes it holds.
    pub fn len(&self) -> usize {
        self.secret.len
    }

    /// Whether it holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.secret.len == 0
    }

    /// The most bytes it holds.
    pub fn capacity(&self) -> usize {
        self.secret.capacity()
    }

    /// Whether the pages refuse every access now, as the system confirmed when they were last
    /// closed.
    pub fn is_closed(&self) -> bool {
        self.access == Access::Nothing
    }

    /// As [`Secret::is_locked`].
    pub fn is_locked(&self) -> bool {
        self.secret.is_locked()
    }

    /// As [`Secret::is_out_of_dumps`].
    pub fn is_out_of_dumps(&self) -> bool {
        self.secret.is_out_of_dumps()
    }

    /// As [`Secret::is_out_of_children`].
    pub fn is_out_of_children(&self) -> bool {
        self.secret.is_out_of_children()
    }
}

impl Drop for ClosedSecret {
    fn drop(&mut self) {
        // Open for the wipe in the drop of the secret that follows; pages that stay closed to
        // writing end the process rather than keep the bytes unwiped.
        open(
            self.secret.pages.region(),
            Access::ReadWrite,
            &mut self.access,
        );
    }
}

impl fmt::Debug for ClosedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClosedSecret(hidden)")
    }
}

/// What the pages allow after the system was asked to change `current` to `wanted`: `wanted` when
/// it agreed, else what they allowed before.
fn after(current: Access, wanted: Access, agreed: bool) -> Access {
    if agreed { wanted } else { current }
}

/// Whether pages that allow `has` can serve a use that needs `needs`.
fn serves(has: Access, needs: Access) -> bool {
    match needs {
        Access::Nothing => true,
        Access::Read => has != Access::Nothing,
        Access::ReadWrite => has == Access::ReadWrite,
    }
}

/// Opens `region` for `needs` and records what it allows now. When the system refuses and what
/// the pages allow does not serve the use, the process ends here: a reference to them would be
/// undefined behaviour, and the access a fault.
fn open(region: Region, needs: Access, access: &mut Access) {
    *access = after(*access, needs, region.allow(needs));
    if !serves(*access, needs) {
        std::process::abort();
    }
}

/// Pages opened for one use, closed again when it ends, by its return or by a panic.
struct Open<'a> {
    region: Region,
    access: &'a mut Access,
}

impl<'a> Open<'a> {
    fn new(region: Region, needs: Access, access: &'a mut Access) -> Self {
        open(region, needs, access);
        Self { region, access }
    }
}

impl Drop for Open<'_> {
    fn drop(&mut self) {
        *self.access = after(
            *self.access,
            Access::Nothing,
            self.region.allow(Access::Nothing),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a use may rely on after every answer of the system, from every state of the pages.
    #[test]
    fn a_refused_change_keeps_what_the_pages_allowed() {
        let all = [Access::Nothing, Access::Read, Access::ReadWrite];
        for current in all {
            for wanted in all {
                assert_eq!(after(current, wanted, true), wanted);
                assert_eq!(after(current, wanted, false), current);
            }
        }
        // Pages left open for reading by a refused close do not serve a write.
        assert!(serves(Access::Read, Access::Read));
        assert!(!serves(Access::Read, Access::ReadWrite));
        assert!(!serves(Access::Nothing, Access::Read));
        assert!(
            serves(Access::ReadWrite, Access::Read) && serves(Access::Nothing, Access::Nothing)
        );
    }

    /// When the system refuses to close the pages after a read, the secret says it is open and
    /// remembers that it is open for reading only; later uses work, and the next close counts.
    #[cfg(unix)]
    #[test]
    fn a_refused_close_is_remembered() {
        let mut secret = ClosedSecret::with_capacity(8);
        secret.push(b"public").unwrap();
        assert!(secret.is_closed());
        let length = secret.read(|bytes| {
            crate::os::refuse_changes(1);
            bytes.len()
        });
        assert_eq!((length, secret.access), (6, Access::Read));
        assert!(!secret.is_closed());
        // A refused opening for reading does not matter: the pages already allow it.
        crate::os::refuse_changes(1);
        assert_eq!(secret.read(<[u8]>::to_vec), b"public");
        assert!(secret.is_closed());
        secret.write(|bytes| bytes[0] = b'P');
        assert_eq!(secret.read(<[u8]>::to_vec), b"Public");
        // A use that panics still closes the pages.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            secret.write(|_| panic!("a use that fails"));
        }));
        assert!(panicked.is_err() && secret.is_closed());
    }
}
