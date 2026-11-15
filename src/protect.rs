//! Protection of secrets: [`Secret`], the buffer a secret lives in, such as a key, a typed line or
//! a row of output; [`WorkArea`], the pages of a computation that holds secrets; [`Isolation`],
//! what the process does against a secret leaving it; and [`write_secret`], the output of a secret.

use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::io::{self, Write};

use zeroize::Zeroize;

use crate::os::Pages;

mod closed;
mod options;

pub use closed::ClosedSecret;
pub use options::{Missing, Options, Protection};

/// Why bytes were not put in a [`Secret`], or a buffer was not made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretError {
    /// The bytes do not fit: the buffer holds `capacity` bytes and never grows. Nothing was written.
    Full {
        /// The most bytes the buffer holds.
        capacity: usize,
    },
    /// The system did not lock the pages in memory, so that they could reach swap; they were given
    /// back before any byte was put in them. A lock limit, such as `RLIMIT_MEMLOCK`, is the usual
    /// reason.
    NotLocked,
    /// The system gave no pages for a work area.
    NoMemory,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full { capacity } => write!(f, "a secret buffer of {capacity} bytes has no room"),
            Self::NotLocked => f.write_str("the system did not lock the memory for the secret"),
            Self::NoMemory => f.write_str("the system gave no memory for the work area"),
        }
    }
}

impl std::error::Error for SecretError {}

/// A buffer for a secret in memory pages of its own: locked against swap, kept out of core dumps and
/// child processes where the system allows, between guard pages, and wiped on drop. It never grows,
/// so it leaves no copies. A failed lock doesn't fail the call: check [`Secret::is_locked`] or use
/// [`Secret::locked`]. If the process aborts, drops don't run and only the lock and dump settings
/// protect the bytes. What each system does: docs/TECHNICAL.md.
pub struct Secret {
    pages: Pages,
    capacity: usize,
    len: usize,
}

impl Secret {
    /// An empty buffer that holds up to `bytes` bytes. Like a `Vec`, it ends the process when the
    /// system has no memory for it.
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            // mmap and VirtualAlloc refuse a length of zero.
            pages: Pages::new(bytes.max(1)),
            capacity: bytes,
            len: 0,
        }
    }

    /// Like [`Secret::with_capacity`], but refuses with [`SecretError::NotLocked`] when the system
    /// does not lock the pages, before any byte is put in them: for a program that takes no secret
    /// into memory that could reach swap. On Linux secret memory counts as locked.
    pub fn locked(bytes: usize) -> Result<Self, SecretError> {
        let secret = Self::with_capacity(bytes);
        if secret.is_locked() {
            Ok(secret)
        } else {
            Err(SecretError::NotLocked)
        }
    }

    /// Appends `bytes`, or refuses with [`SecretError::Full`] and writes nothing when they do not
    /// fit.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), SecretError> {
        let full = SecretError::Full {
            capacity: self.capacity,
        };
        let end = self
            .len
            .checked_add(bytes.len())
            .filter(|&end| end <= self.capacity)
            .ok_or(full)?;
        self.pages.as_mut_slice()[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    /// Shortens the contents to `len` bytes and wipes what it cuts; a longer `len` changes
    /// nothing.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.pages.as_mut_slice()[len..self.len].zeroize();
            self.len = len;
        }
    }

    /// The bytes pushed so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.pages.as_slice()[..self.len]
    }

    /// The bytes as text, or `None` when they are not UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()).ok()
    }

    /// The most bytes it holds.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Whether the system keeps the pages in memory, never in swap.
    pub fn is_locked(&self) -> bool {
        self.pages.is_locked()
    }

    /// Whether the system leaves these pages out of the dumps it writes of the process.
    pub fn is_out_of_dumps(&self) -> bool {
        self.pages.is_out_of_dumps()
    }

    /// Whether a child process gets none of the bytes: no mapping of the pages, or zeros in their
    /// place, as the system confirmed when they were made.
    pub fn is_out_of_children(&self) -> bool {
        self.pages.is_out_of_children()
    }

    /// A buffer of `bytes` zero bytes, to be written in place through [`Secret::as_mut_bytes`].
    pub fn zeroed(bytes: usize) -> Self {
        let mut secret = Self::with_capacity(bytes);
        secret.len = bytes;
        secret
    }

    /// The bytes pushed so far, to change in place; as a slice, they cannot outgrow the buffer.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.pages.as_mut_slice()[..self.len]
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Volatile writes, which the compiler keeps although nothing reads the bytes again.
        self.pages.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(hidden)")
    }
}

/// Pages for the work of a computation that holds secrets, such as the memory of a password hash:
/// whole pages of its own, zero when made, locked where the system allows it and its lock limit
/// holds all of them, kept out of core dumps and child processes as a [`Secret`]'s are, and wiped
/// before they are given back. Unlike a [`Secret`] they are never Linux secret memory, so that a
/// large area does not keep the machine from hibernating.
pub struct WorkArea {
    pages: Pages,
}

impl WorkArea {
    /// A work area of `bytes` bytes, at least one, or `None` when the system refuses the pages.
    pub fn new(bytes: usize) -> Option<Self> {
        Pages::work_area(bytes.max(1)).map(|pages| Self { pages })
    }

    /// Like [`WorkArea::new`], but refuses with [`SecretError::NotLocked`] when the system does not
    /// lock all the pages, and with [`SecretError::NoMemory`] when it gives none. A large area,
    /// such as the memory of a password hash, often exceeds the lock limit; a program that requires
    /// it locked then stops before it reads the secret, rather than computing with less memory.
    pub fn locked(bytes: usize) -> Result<Self, SecretError> {
        let area = Self::new(bytes).ok_or(SecretError::NoMemory)?;
        if area.is_locked() {
            Ok(area)
        } else {
            Err(SecretError::NotLocked)
        }
    }

    /// The bytes of the area.
    pub fn as_slice(&self) -> &[u8] {
        self.pages.as_slice()
    }

    /// The bytes of the area, to change in place.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.pages.as_mut_slice()
    }

    /// Whether the system keeps the pages in memory, never in swap.
    pub fn is_locked(&self) -> bool {
        self.pages.is_locked()
    }

    /// Whether the system leaves these pages out of the dumps it writes of the process.
    pub fn is_out_of_dumps(&self) -> bool {
        self.pages.is_out_of_dumps()
    }

    /// Whether a child process gets none of the bytes, as for a [`Secret`].
    pub fn is_out_of_children(&self) -> bool {
        self.pages.is_out_of_children()
    }
}

impl Drop for WorkArea {
    fn drop(&mut self) {
        self.pages.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for WorkArea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WorkArea({} bytes, hidden)", self.as_slice().len())
    }
}

/// What holds against a secret leaving the process, as [`Isolation::enter`] read it back after it
/// applied what the system offers: a field is true only when reading it back confirmed it, so a
/// refusal of the system shows as false.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Isolation {
    /// On Unix a crash writes no core dump: RLIMIT_CORE is 0, and on Linux and Android the process
    /// is not dumpable, which a pipe in `core_pattern` respects too. False on Windows, whose error
    /// reports, which [`Isolation::enter`] keeps from the heap, still hold the threads' stacks and
    /// registers.
    pub no_core_dumps: bool,
    /// Other programs of the same user cannot open the process to read or change its memory, nor
    /// on Windows its threads to read or change their registers; and no debugger was attached
    /// before, which would keep reading.
    pub no_memory_reading: bool,
    /// No new socket can be opened, nor on Linux and Android an io_uring, which could open one; on
    /// macOS a socket can still be made, but the sandbox refuses to bind or connect it.
    pub no_new_sockets: bool,
    /// The process runs in a network namespace of its own, with only a loopback interface, which
    /// stays down, and no route (Linux).
    pub empty_network: bool,
    /// Files cannot be opened for writing, created, renamed or removed, apart from the exceptions
    /// [`Isolation::enter`] names for each system; what else is refused depends on the system too.
    /// False on Windows, whose low integrity level still writes where a low label allows it, and
    /// on Linux where no seccomp filter is written, whose Landlock layer leaves modes, owners,
    /// extended attributes and times.
    pub no_file_changes: bool,
    /// The processor's speculation that leaks across programs is limited for the calling thread
    /// and what it starts, against Spectre variants 4 and 2: speculative store bypass and indirect
    /// branch speculation are disabled for good, the system disables them for every program, or
    /// the processor is not affected (Linux and Android); on Windows, side-channel isolation.
    pub speculation_limited: bool,
    /// The protections above cover every thread of the process, not only the calling one.
    pub whole_process: bool,
    /// File locks are refused (Linux and Android, with [`Options::refuse_file_locks`]).
    pub file_locks_refused: bool,
    /// `sendmsg` is refused (Linux and Android, with [`Options::refuse_sendmsg`]).
    pub sendmsg_refused: bool,
    /// No new executable code can run (Windows, with [`Options::refuse_dynamic_code`]).
    pub dynamic_code_refused: bool,
    /// Only DLLs signed by Microsoft load (Windows, with [`Options::microsoft_signed_only`]).
    pub microsoft_signed_only: bool,
    /// No signal reaches another process: Landlock from Linux 6.12, or
    /// [`Options::signals_to_self_only`] (Linux and Android).
    pub foreign_signals_refused: bool,
    /// Every page of the process stays out of swap ([`Options::lock_all_memory`], Linux and
    /// Android).
    pub memory_locked: bool,
}

impl Isolation {
    /// Closes the process against a secret leaving it, for good, and returns what actually took effect.
    /// Call it before reading a secret. Refusals show up as `false`, never as errors, and descriptors
    /// opened earlier stay usable. Protections that can break programs are in
    /// [`Isolation::enter_with`]; [`Isolation::enter_requiring`] stops if a required one is missing.
    /// What each system applies is listed in docs/TECHNICAL.md.
    pub fn enter() -> Self {
        crate::os::enter(Options::new())
    }

    /// As [`Isolation::enter`], with the protections that `options` turns on as well.
    pub fn enter_with(options: Options) -> Self {
        crate::os::enter(options)
    }

    /// The strict mode: as [`Isolation::enter_with`], but refuses with [`Missing`] when a
    /// protection in `required` does not read back, so that a program stops before it reads a
    /// secret. What was applied stays applied either way.
    pub fn enter_requiring(options: Options, required: &[Protection]) -> Result<Self, Missing> {
        Self::enter_with(options).require(required)
    }

    /// `Ok` with this answer when every protection in `required` holds, else [`Missing`].
    pub fn require(self, required: &[Protection]) -> Result<Self, Missing> {
        let missing: Vec<Protection> = Protection::ALL
            .into_iter()
            .filter(|protection| required.contains(protection) && !self.has(*protection))
            .collect();
        if missing.is_empty() {
            Ok(self)
        } else {
            Err(Missing {
                missing,
                isolation: self,
            })
        }
    }

    /// Whether `protection` holds, as its field says.
    pub fn has(&self, protection: Protection) -> bool {
        match protection {
            Protection::NoCoreDumps => self.no_core_dumps,
            Protection::NoMemoryReading => self.no_memory_reading,
            Protection::NoNewSockets => self.no_new_sockets,
            Protection::EmptyNetwork => self.empty_network,
            Protection::NoFileChanges => self.no_file_changes,
            Protection::SpeculationLimited => self.speculation_limited,
            Protection::WholeProcess => self.whole_process,
            Protection::FileLocksRefused => self.file_locks_refused,
            Protection::SendmsgRefused => self.sendmsg_refused,
            Protection::DynamicCodeRefused => self.dynamic_code_refused,
            Protection::MicrosoftSignedOnly => self.microsoft_signed_only,
            Protection::ForeignSignalsRefused => self.foreign_signals_refused,
            Protection::MemoryLocked => self.memory_locked,
        }
    }

    /// Every protection with whether it holds, how far it reaches and what confirmed it, for a
    /// program that shows the details.
    pub fn measures(&self) -> Vec<Measure> {
        Protection::ALL
            .into_iter()
            .map(|protection| {
                let (process_wide, proof) = crate::os::measure(protection);
                Measure {
                    protection,
                    holds: self.has(protection),
                    reach: if process_wide || self.whole_process {
                        Reach::Process
                    } else {
                        Reach::Thread
                    },
                    proof,
                }
            })
            .collect()
    }

    /// One bit for each protection that holds, in the order of [`Protection::ALL`]: how a worker
    /// tells its parent.
    pub(crate) fn to_bits(self) -> u32 {
        Protection::ALL
            .into_iter()
            .enumerate()
            .filter(|(_, protection)| self.has(*protection))
            .fold(0, |bits, (index, _)| bits | 1 << index)
    }

    /// The answer that [`Isolation::to_bits`] made.
    pub(crate) fn from_bits(bits: u32) -> Self {
        let has = |protection: Protection| {
            Protection::ALL
                .iter()
                .position(|&each| each == protection)
                .is_some_and(|index| bits & 1 << index != 0)
        };
        Self {
            no_core_dumps: has(Protection::NoCoreDumps),
            no_memory_reading: has(Protection::NoMemoryReading),
            no_new_sockets: has(Protection::NoNewSockets),
            empty_network: has(Protection::EmptyNetwork),
            no_file_changes: has(Protection::NoFileChanges),
            speculation_limited: has(Protection::SpeculationLimited),
            whole_process: has(Protection::WholeProcess),
            file_locks_refused: has(Protection::FileLocksRefused),
            sendmsg_refused: has(Protection::SendmsgRefused),
            dynamic_code_refused: has(Protection::DynamicCodeRefused),
            microsoft_signed_only: has(Protection::MicrosoftSignedOnly),
            foreign_signals_refused: has(Protection::ForeignSignalsRefused),
            memory_locked: has(Protection::MemoryLocked),
        }
    }
}

/// How far a protection reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// The calling thread and the threads it starts afterwards.
    Thread,
    /// Every thread of the process.
    Process,
}

/// One protection in detail, as [`Isolation::measures`] gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measure {
    /// Which protection.
    pub protection: Protection,
    /// Whether it holds.
    pub holds: bool,
    /// How far it reaches.
    pub reach: Reach,
    /// What confirmed it, or why this system doesn't offer it.
    pub proof: &'static str,
}

/// Writes `text` to standard output without leaving a copy in the standard library's buffer: it
/// flushes that buffer first, then writes the bytes directly.
#[cfg(not(target_arch = "wasm32"))]
pub fn write_secret(text: &str) -> io::Result<()> {
    io::stdout().flush()?;
    crate::os::write_secret(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pushed_bytes_stay_within_the_capacity() {
        let mut secret = Secret::with_capacity(8);
        secret.push(b"public").unwrap();
        assert_eq!(
            secret.push(b"bytes"),
            Err(SecretError::Full { capacity: 8 })
        );
        assert_eq!(
            secret.as_bytes(),
            b"public",
            "a refused push writes nothing"
        );
        secret.push(b"!!").unwrap();
        assert_eq!(secret.as_str(), Some("public!!"));
        assert_eq!(secret.capacity(), 8);
        let mut empty = Secret::with_capacity(0);
        assert_eq!(empty.push(b""), Ok(()));
        assert_eq!(empty.push(b"x"), Err(SecretError::Full { capacity: 0 }));
    }

    #[test]
    fn truncation_wipes_what_it_cuts() {
        let mut secret = Secret::with_capacity(16);
        secret.push(b"public test").unwrap();
        secret.truncate(6);
        assert_eq!(secret.as_bytes(), b"public");
        assert_eq!(
            &secret.pages.as_slice()[..16],
            b"public\0\0\0\0\0\0\0\0\0\0"
        );
        secret.truncate(10);
        assert_eq!(secret.as_bytes(), b"public");
        secret.push(&[0xff]).unwrap();
        assert_eq!(secret.as_str(), None);
    }

    /// One page fits any usual RLIMIT_MEMLOCK (64 KiB or more) and any working set.
    #[test]
    fn a_secret_is_locked_and_out_of_dumps_where_the_system_allows() {
        let secret = Secret::with_capacity(1024);
        assert_eq!(secret.is_locked(), cfg!(any(unix, windows)));
        assert_eq!(
            secret.is_out_of_dumps(),
            cfg!(any(target_os = "linux", target_os = "android", windows))
        );
        assert_eq!(
            secret.is_out_of_children(),
            cfg!(any(
                target_os = "linux",
                target_os = "android",
                target_vendor = "apple",
                windows
            ))
        );
        let area = WorkArea::new(4096).unwrap();
        assert_eq!(area.is_out_of_children(), secret.is_out_of_children());
        assert_eq!(area.is_out_of_dumps(), secret.is_out_of_dumps());
    }

    /// The range and the permissions of the mapping that holds `address`, as /proc/self/maps lists
    /// them.
    #[cfg(target_os = "linux")]
    fn mapping(address: usize) -> (std::ops::Range<usize>, String) {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        maps.lines()
            .find_map(|line| {
                let (range, rest) = line.split_once(' ')?;
                let (start, end) = range.split_once('-')?;
                let bound = |hex| usize::from_str_radix(hex, 16).unwrap();
                let range = bound(start)..bound(end);
                range
                    .contains(&address)
                    .then(|| (range, rest[..4].to_owned()))
            })
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn permissions(address: usize) -> String {
        mapping(address).1
    }

    /// A page that refuses every access lies on each side of a secret's pages and of a work area.
    #[cfg(target_os = "linux")]
    #[test]
    fn guard_pages_lie_on_both_sides() {
        let secret = Secret::with_capacity(5000);
        let area = WorkArea::new(10_000).unwrap();
        for start in [
            secret.as_bytes().as_ptr() as usize,
            area.as_slice().as_ptr() as usize,
        ] {
            let (range, open) = mapping(start);
            assert_eq!((range.start, &open[..2]), (start, "rw"));
            assert!(permissions(range.start - 1).starts_with("---"));
            assert!(permissions(range.end).starts_with("---"));
        }
    }

    /// A closed secret's pages refuse every access but during a use, and close again after a use
    /// that panicked.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_closed_secret_opens_only_for_a_use() {
        let mut secret = ClosedSecret::with_capacity(32);
        secret.push(b"public test").unwrap();
        assert!(secret.is_closed());
        let (address, open) = secret.read(|bytes| {
            let address = bytes.as_ptr() as usize;
            (address, permissions(address))
        });
        assert!(open.starts_with("r-"), "{open}");
        assert!(permissions(address).starts_with("---"));
        assert_eq!(secret.read(<[u8]>::to_vec), b"public test");
        secret.write(|bytes| bytes[0] = b'P');
        secret.truncate(6);
        assert_eq!(secret.read(<[u8]>::to_vec), b"Public");
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            secret.read(|_| panic!("a use that fails"));
        }));
        assert!(panicked.is_err());
        assert!(secret.is_closed() && permissions(address).starts_with("---"));
        assert_eq!(
            secret.push(&[0; 27]),
            Err(SecretError::Full { capacity: 32 })
        );
        assert_eq!((secret.len(), secret.capacity()), (6, 32));
        assert_eq!(format!("{secret:?}"), "ClosedSecret(hidden)");
    }

    /// Two pages of the largest size in use, 64 KiB: Linux touches every page before handing it
    /// out, and that must leave no trace.
    #[test]
    fn a_zeroed_secret_holds_only_zeros_on_every_page() {
        let secret = Secret::zeroed(128 << 10);
        assert!(secret.as_bytes().iter().all(|&byte| byte == 0));
    }

    /// Every protection has a measure, which agrees with the field it names and says what
    /// confirmed it.
    #[test]
    fn measures_cover_every_protection() {
        let isolation = Isolation {
            no_core_dumps: true,
            ..Isolation::default()
        };
        let measures = isolation.measures();
        assert_eq!(measures.len(), Protection::ALL.len());
        for measure in &measures {
            assert_eq!(measure.holds, isolation.has(measure.protection));
            assert!(!measure.proof.is_empty());
        }
        if cfg!(target_os = "linux") {
            let socket = measures
                .iter()
                .find(|measure| measure.protection == Protection::NoNewSockets)
                .unwrap();
            assert_eq!(socket.reach, Reach::Thread);
        }
    }

    #[test]
    fn debug_output_hides_the_bytes() {
        let mut secret = Secret::with_capacity(8);
        secret.push(b"public").unwrap();
        assert_eq!(format!("{secret:?}"), "Secret(hidden)");
    }
}
