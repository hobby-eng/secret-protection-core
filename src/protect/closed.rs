//! [`ClosedSecret`]: a secret whose pages refuse every access between uses.

use std::fmt;

use super::{Secret, SecretError};
use crate::os::{Access, Region};

/// Like [`Secret`], but its pages refuse all access between uses. The bytes are reachable only
/// inside [`ClosedSecret::read`] and [`ClosedSecret::write`], so a stray read elsewhere in the
/// program (a Heartbleed-style bug) crashes instead of leaking. Each use costs two system calls.
pub struct ClosedSecret {
    secret: Secret,
    closed: bool,
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
        let closed = secret.pages.region().allow(Access::Nothing);
        Self { secret, closed }
    }

    /// Appends `bytes`, as [`Secret::push`].
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), SecretError> {
        let _open = Open::new(
            self.secret.pages.region(),
            Access::ReadWrite,
            &mut self.closed,
        );
        self.secret.push(bytes)
    }

    /// Shortens the contents to `len` bytes and wipes what it cuts, as [`Secret::truncate`].
    pub fn truncate(&mut self, len: usize) {
        let _open = Open::new(
            self.secret.pages.region(),
            Access::ReadWrite,
            &mut self.closed,
        );
        self.secret.truncate(len);
    }

    /// Opens the pages for reading, hands the bytes pushed so far to `use_bytes`, and closes them
    /// again.
    pub fn read<R>(&mut self, use_bytes: impl FnOnce(&[u8]) -> R) -> R {
        let _open = Open::new(self.secret.pages.region(), Access::Read, &mut self.closed);
        use_bytes(self.secret.as_bytes())
    }

    /// Opens the pages for reading and writing, hands the bytes pushed so far to `change`, and
    /// closes them again.
    pub fn write<R>(&mut self, change: impl FnOnce(&mut [u8]) -> R) -> R {
        let _open = Open::new(
            self.secret.pages.region(),
            Access::ReadWrite,
            &mut self.closed,
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
        self.closed
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
        // Open for the wipe in the drop of the secret that follows; a refusal ends the process
        // rather than leaving the bytes unwiped.
        if !self.secret.pages.region().allow(Access::ReadWrite) && self.closed {
            std::process::abort();
        }
    }
}

impl fmt::Debug for ClosedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClosedSecret(hidden)")
    }
}

/// Pages opened for one use, closed again when it ends, by its return or by a panic.
struct Open<'a> {
    region: Region,
    closed: &'a mut bool,
}

impl<'a> Open<'a> {
    /// Opens `region` for `access`. Where the pages are closed and the system refuses to open them,
    /// the process ends here: a reference to them would be undefined behaviour, and the access a
    /// fault.
    fn new(region: Region, access: Access, closed: &'a mut bool) -> Self {
        if !region.allow(access) && *closed {
            std::process::abort();
        }
        Self { region, closed }
    }
}

impl Drop for Open<'_> {
    fn drop(&mut self) {
        *self.closed = self.region.allow(Access::Nothing);
    }
}
