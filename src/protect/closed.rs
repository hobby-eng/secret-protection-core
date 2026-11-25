//! [`ClosedSecret`] requests page protection between uses and reports whether the OS granted it.

use std::fmt;

use super::{Secret, SecretError};
use crate::os::{Access, Region};

/// A [`Secret`] that asks the OS to deny access to its pages between uses. Check
/// [`ClosedSecret::is_closed`] after each use if closing is required. WebAssembly has no
/// per-buffer page permissions. On Windows a lock and a closure exclude each other, as Windows
/// unlocks a page it makes inaccessible: [`ClosedSecret::locked`] keeps the lock and leaves the
/// pages open, [`ClosedSecret::with_capacity`] closes them and gives the lock up. On Unix a
/// continuing child must leave pre-fork byte references unused. If the callback returns or unwinds
/// in that child, its guard skips the permission change.
pub struct ClosedSecret {
    secret: Secret,
    state: State,
}

/// Whether closing pages takes their lock away: Windows unlocks a page it makes inaccessible
/// (`STATUS_WAS_UNLOCKED`), and the page file may then take it.
const CLOSING_UNLOCKS: bool = cfg!(windows);

/// What the pages allow, and what closing them does.
struct State {
    /// What the pages allow now, as the system last confirmed.
    access: Access,
    /// Whether the pages close between uses: not those that would lose a lock asked for.
    closes: bool,
    /// Whether a closing took the lock of the pages away.
    unlocked: bool,
}

impl State {
    /// Asks the system to close the pages, where they close at all.
    fn close(&mut self, region: Region) {
        if self.closes {
            self.access = after(self.access, Access::Nothing, region.allow(Access::Nothing));
            self.unlocked |= CLOSING_UNLOCKS && self.access == Access::Nothing;
        }
    }
}

impl ClosedSecret {
    /// Creates an empty [`Secret`] and asks the OS to close its pages. Check [`Self::is_closed`]
    /// if the application requires closure. On Windows the first closing takes the lock away
    /// ([`Self::is_locked`]).
    pub fn with_capacity(bytes: usize) -> Self {
        Self::closing(Secret::with_capacity(bytes), false)
    }

    /// As [`Secret::locked`]: refuses with [`SecretError::NotLocked`] when the system does not lock
    /// the pages. On Windows the pages stay open to keep the lock, and [`Self::is_closed`] is
    /// false.
    pub fn locked(bytes: usize) -> Result<Self, SecretError> {
        Secret::locked(bytes).map(|secret| Self::closing(secret, true))
    }

    fn closing(secret: Secret, keeps_lock: bool) -> Self {
        // New pages allow reading and writing until the system agrees to close them.
        let mut state = State {
            access: Access::ReadWrite,
            closes: !(keeps_lock && CLOSING_UNLOCKS),
            unlocked: false,
        };
        state.close(secret.pages.region());
        Self { secret, state }
    }

    /// Appends `bytes`, as [`Secret::push`].
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), SecretError> {
        let _open = Open::new(
            self.secret.pages.region(),
            Access::ReadWrite,
            &mut self.state,
        );
        self.secret.push(bytes)
    }

    /// Shortens the contents to `len` bytes and wipes what it cuts, as [`Secret::truncate`].
    pub fn truncate(&mut self, len: usize) {
        let _open = Open::new(
            self.secret.pages.region(),
            Access::ReadWrite,
            &mut self.state,
        );
        self.secret.truncate(len);
    }

    /// Passes the stored bytes to `use_bytes` for reading and requests closure when it returns.
    pub fn read<R>(&mut self, use_bytes: impl FnOnce(&[u8]) -> R) -> R {
        let _open = Open::new(self.secret.pages.region(), Access::Read, &mut self.state);
        use_bytes(self.secret.as_bytes())
    }

    /// Passes the stored bytes to `change` for writing and requests closure when it returns.
    pub fn write<R>(&mut self, change: impl FnOnce(&mut [u8]) -> R) -> R {
        let _open = Open::new(
            self.secret.pages.region(),
            Access::ReadWrite,
            &mut self.state,
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

    /// Whether the OS last confirmed that these pages deny access. An inherited owner reports
    /// false in a continuing child of ordinary Unix `fork`.
    pub fn is_closed(&self) -> bool {
        self.secret.pages.here() && self.state.access == Access::Nothing
    }

    /// As [`Secret::is_locked`], until a closing takes the lock away, as on Windows.
    pub fn is_locked(&self) -> bool {
        self.secret.is_locked() && !self.state.unlocked
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
        // writing end the process rather than keep the bytes unwiped. A child of `fork` leaves
        // its parent's pages alone.
        if self.secret.pages.here() {
            open(
                self.secret.pages.region(),
                Access::ReadWrite,
                &mut self.state,
            );
        }
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

/// Opens `region` for `needs` and records what it allows now; pages that never close stay open
/// for reading and writing. When the system refuses and what the pages allow does not serve the
/// use, the process ends here: a reference to them would be undefined behaviour, and the access a
/// fault.
fn open(region: Region, needs: Access, state: &mut State) {
    if !state.closes {
        return;
    }
    state.access = after(state.access, needs, region.allow(needs));
    if !serves(state.access, needs) {
        std::process::abort();
    }
}

/// Pages opened for one use, closed again when it ends, by its return or by a panic.
struct Open<'a> {
    region: Region,
    state: &'a mut State,
}

impl<'a> Open<'a> {
    fn new(region: Region, needs: Access, state: &'a mut State) -> Self {
        open(region, needs, state);
        Self { region, state }
    }
}

impl Drop for Open<'_> {
    fn drop(&mut self) {
        self.state.close(self.region);
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

    /// Fault: the system refuses a change of access, as it does under a policy or without
    /// memory. When it refuses to close the pages after a read, the secret says it is open and
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
        assert_eq!((length, secret.state.access), (6, Access::Read));
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
