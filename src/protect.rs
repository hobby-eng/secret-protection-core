//! Protection of secrets: [`Secret`], the buffer a secret lives in, such as a key, a typed line or
//! a row of output; [`WorkArea`], the pages of a computation that holds secrets; [`Isolation`],
//! what the process does against a secret leaving it; and [`write_secret`], the output of a secret.

use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::io::{self, Write};

use zeroize::Zeroize;

use crate::os::Pages;

mod closed;
#[cfg(unix)]
mod folder;
mod options;

pub use closed::ClosedSecret;
#[cfg(unix)]
pub use folder::WritableFolder;
pub use options::{Missing, Options, Outcome, Protection};

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

/// A buffer for a secret in pages of its own: locked, out of core dumps and child processes where
/// the system allows, between guard pages (a heap buffer in WebAssembly), wiped on drop, never
/// grown. A failed lock doesn't fail the call: check [`Secret::is_locked`] or use
/// [`Secret::locked`]. A child of `fork` must leave its parent's buffers alone. What each system
/// does, and what an abort or a `fork` leaves: docs/TECHNICAL.md.
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
        // Volatile writes, which the compiler keeps although nothing reads the bytes again. A
        // child of `fork` leaves its parent's pages alone: they are gone there, or zeros.
        if self.pages.here() {
            self.pages.as_mut_slice().zeroize();
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(hidden)")
    }
}

/// Fixed-size scratch storage for a computation that handles secrets. It starts zeroed and
/// wipes on drop. Unix and Windows allocate dedicated pages with guards and attempt to lock
/// them where supported. WebAssembly uses a heap allocation. Linux uses anonymous pages here,
/// even when [`Secret`] can use kernel secret memory. See [`WorkArea::is_locked`] and
/// [`WorkArea::is_out_of_children`] for the properties of a particular allocation.
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
        if self.pages.here() {
            self.pages.as_mut_slice().zeroize();
        }
    }
}

impl fmt::Debug for WorkArea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WorkArea({} bytes, hidden)", self.as_slice().len())
    }
}

/// What holds against a secret leaving the process, as [`Isolation::enter`] read it back. A field
/// is true only when the call confirmed the protection. [`Isolation::outcome`] tells the rest
/// apart: refused, not asked for, not offered on this system, or not checkable.
///
/// The fields are a copy made at entry, for reading. [`Isolation::has`], [`Isolation::require`],
/// [`Isolation::require_process_wide`] and worker admission read the recorded outcomes instead, so
/// changing a field changes none of their answers.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Isolation {
    /// On Unix a crash writes no core dump: RLIMIT_CORE is 0, and on Linux and Android the process
    /// is not dumpable, which a pipe in `core_pattern` respects too. Not offered on Windows, whose
    /// error reports still hold the threads' stacks and registers; [`Isolation::enter`] asks them
    /// to leave out the heap, which Windows does not let it read back.
    pub no_core_dumps: bool,
    /// The platform confirmed its restrictions on new access to the process's memory. On
    /// Windows the check covers current process and thread access controls and debugger status.
    /// Access already granted to an existing handle can remain usable. On Linux the answer is
    /// unknown when an outside tracer could be hidden and no observed tracer or dumpable flag
    /// already warrants refusal.
    pub no_memory_reading: bool,
    /// No new socket can be opened, nor on Linux and Android an io_uring, which could open one; on
    /// macOS a socket can still be made, but the sandbox refuses to bind or connect it. On Windows
    /// it is the policy of the worker's AppContainer token, which has no network capability: what
    /// is confirmed is that token, not a socket refused or a connection tried.
    pub no_new_sockets: bool,
    /// Linux recorded namespace setup, saw no listed interface other than loopback, and found
    /// no IPv4 routes. The check does not read interface flags or the IPv6 routing table.
    pub empty_network: bool,
    /// Files cannot be opened for writing, created, renamed or removed, apart from the exceptions
    /// docs/TECHNICAL.md names for each system and beneath folders `enter_with_folders` granted.
    /// Not offered on Windows, whose low integrity level still writes where a low label allows it; refused on Linux without the seccomp filter,
    /// whose Landlock layer alone leaves modes, owners, extended attributes and times.
    pub no_file_changes: bool,
    /// Linux and Android require both mitigation states to be permanently disabled or unnecessary.
    /// A reversible or enabled state gives `Refused`. Otherwise an unreadable state gives `Unknown`.
    /// Windows checks its side-channel mitigation policy.
    pub speculation_limited: bool,
    /// Whether isolation has process scope. Check the outcome and reach of each protection
    /// an application needs.
    pub whole_process: bool,
    /// File locks are refused (Linux and Android, with [`Options::refuse_file_locks`]).
    pub file_locks_refused: bool,
    /// `sendmsg` is refused (Linux and Android, with [`Options::refuse_sendmsg`]).
    pub sendmsg_refused: bool,
    /// No new executable code can run, with no way for a thread or another process to opt out
    /// (Windows, with [`Options::refuse_dynamic_code`]).
    pub dynamic_code_refused: bool,
    /// Only DLLs signed by Microsoft load (Windows, with [`Options::microsoft_signed_only`]).
    pub microsoft_signed_only: bool,
    /// Signals go only to this process itself ([`Options::signals_to_self_only`], Linux and
    /// Android).
    pub signals_to_self_only: bool,
    /// Signals go only to processes inside this one's Landlock layer: itself and the children it
    /// starts afterwards (Linux 6.12 and later).
    pub signals_within_layer: bool,
    /// Every page of the process stays out of swap ([`Options::lock_all_memory`], Linux and
    /// Android), unless the program itself unlocks them.
    pub memory_locked: bool,
    /// No other program can be started, which would carry a secret out in its command line or
    /// input: on Linux and Android the filter refuses `execve`, on Windows the child-process
    /// policy holds. macOS reports unknown after sandbox entry and refused if entry failed.
    pub no_new_programs: bool,
    /// Windows confirmed its extension-point and image-load policies, and the crate set the
    /// default DLL search to the application directory and System32. The application directory
    /// must be trusted. An explicit path or custom search flags can select another location.
    pub no_planted_libraries: bool,
    /// A job keeps the process from writing the clipboard, from global atoms, from other
    /// programs' windows and from changing the desktop, and allows it one process (Windows).
    /// Reading the clipboard stays, so that a secret can be pasted in.
    pub desktop_restricted: bool,
    /// Windows read low integrity or below on the primary token and on the effective tokens
    /// of the threads it inspected. A later impersonation can change a thread's rights.
    pub low_integrity: bool,
    /// This call granted the folders `enter_with_folders` was given: new files and folders can
    /// be made, written, renamed and removed beneath them, on Linux also linked, and no file
    /// changes anywhere else (Linux with Landlock, and macOS).
    pub folder_writes: bool,
    /// What became of each protection, by its place in [`Protection::ALL`].
    outcomes: [Outcome; Protection::COUNT],
    /// Which protections reach every thread of the process.
    process_wide: [bool; Protection::COUNT],
}

impl Isolation {
    /// Applies the default isolation measures and reports the outcomes observed at entry.
    /// Call this before reading a secret. Existing descriptors may remain usable. To require
    /// particular outcomes, use [`Isolation::enter_requiring`] and handle its result.
    pub fn enter() -> Self {
        crate::os::enter(Options::new())
    }

    /// As [`Isolation::enter`], with the protections that `options` turns on as well.
    pub fn enter_with(options: Options) -> Self {
        crate::os::enter(options)
    }

    /// As [`Isolation::enter_with`], and lets the program make files and folders beneath
    /// `folders`, and nowhere else: [`Protection::FolderWrites`]. Each folder must still be the
    /// new, empty one [`WritableFolder::create`] made, and this must be the process's first
    /// isolation, as a later layer only narrows what an earlier one allows. Linux and macOS;
    /// docs/API.md lists the calls let through.
    #[cfg(unix)]
    pub fn enter_with_folders(options: Options, folders: &[&WritableFolder]) -> Self {
        crate::os::enter_granting(options, folders)
    }

    /// The strict mode: as [`Isolation::enter_with`], but refuses with [`Missing`] when a
    /// protection in `required` is not confirmed, so that a program stops before it reads a
    /// secret. What was applied stays applied either way.
    pub fn enter_requiring(options: Options, required: &[Protection]) -> Result<Self, Missing> {
        Self::enter_with(options).require(required)
    }

    /// As [`Isolation::enter_requiring`], but each protection in `required`, and
    /// [`Protection::WholeProcess`], must also reach every thread of the process
    /// ([`Reach::Process`]): the rule a worker is admitted by.
    pub fn enter_requiring_process_wide(
        options: Options,
        required: &[Protection],
    ) -> Result<Self, Missing> {
        Self::enter_with(options).require_process_wide(required)
    }

    /// `Ok` with this answer when every protection in `required` is confirmed, else [`Missing`].
    pub fn require(self, required: &[Protection]) -> Result<Self, Missing> {
        self.require_in_scope(required, false)
    }

    /// As [`Isolation::require`] with the rule of [`Isolation::enter_requiring_process_wide`].
    pub fn require_process_wide(self, required: &[Protection]) -> Result<Self, Missing> {
        let mut all = required.to_vec();
        all.push(Protection::WholeProcess);
        self.require_in_scope(&all, true)
    }

    pub(crate) fn require_in_scope(
        self,
        required: &[Protection],
        process: bool,
    ) -> Result<Self, Missing> {
        let missing: Vec<Protection> = Protection::ALL
            .into_iter()
            .filter(|protection| {
                required.contains(protection)
                    && (!self.has(*protection) || process && !self.process_wide[protection.index()])
            })
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

    /// Whether this report recorded `protection` as [`Outcome::Confirmed`]. The answer describes
    /// the check performed at isolation time. See [`Isolation::measures`] for its scope and evidence.
    pub fn has(&self, protection: Protection) -> bool {
        self.outcome(protection) == Outcome::Confirmed
    }

    /// What became of `protection` in the call.
    pub fn outcome(&self, protection: Protection) -> Outcome {
        self.outcomes[protection.index()]
    }

    /// Every protection with its outcome, how far it reaches and what the call observed, for a
    /// program that shows the details.
    pub fn measures(&self) -> Vec<Measure> {
        Protection::ALL
            .into_iter()
            .map(|protection| {
                let outcome = self.outcome(protection);
                Measure {
                    protection,
                    outcome,
                    reach: if self.process_wide[protection.index()] {
                        Reach::Process
                    } else {
                        Reach::Thread
                    },
                    evidence: crate::os::evidence(protection, outcome).unwrap_or(match outcome {
                        Outcome::Confirmed => "confirmed",
                        Outcome::Refused => "the system refused it, or it did not read back",
                        Outcome::NotRequested => "the call did not ask for it",
                        Outcome::Unsupported => "not offered on this system",
                        Outcome::Unknown => "it could not be checked",
                    }),
                }
            })
            .collect()
    }

    /// One byte for each protection, in the order of [`Protection::ALL`]: its outcome, and 8 added
    /// when it reaches the whole process. How a worker tells its parent.
    pub(crate) fn to_bytes(self) -> [u8; Protection::COUNT] {
        std::array::from_fn(|index| {
            self.outcomes[index].to_bits() | u8::from(self.process_wide[index]) << 3
        })
    }

    /// The answer that [`Isolation::to_bytes`] made, or `None` for other bytes.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; Protection::COUNT] = bytes.try_into().ok()?;
        let mut findings = Findings::new();
        for (protection, &byte) in Protection::ALL.into_iter().zip(bytes) {
            findings.set(protection, Outcome::from_bits(byte & 7)?, byte & 8 != 0);
        }
        (bytes.iter().all(|&byte| byte < 16)).then(|| findings.finish())
    }
}

/// What a system's module found for each protection, before it becomes an [`Isolation`].
pub(crate) struct Findings {
    outcomes: [Outcome; Protection::COUNT],
    process_wide: [bool; Protection::COUNT],
}

impl Findings {
    /// Nothing found yet: every protection counts as not offered.
    pub(crate) fn new() -> Self {
        Self {
            outcomes: [Outcome::Unsupported; Protection::COUNT],
            process_wide: [false; Protection::COUNT],
        }
    }

    /// Records what became of `protection`, and whether it reaches the whole process.
    pub(crate) fn set(&mut self, protection: Protection, outcome: Outcome, process_wide: bool) {
        self.outcomes[protection.index()] = outcome;
        self.process_wide[protection.index()] = process_wide;
    }

    /// Records `protection` as confirmed when `holds`, else as refused.
    #[cfg(any(unix, windows, test))]
    pub(crate) fn check(&mut self, protection: Protection, holds: bool, process_wide: bool) {
        let outcome = if holds {
            Outcome::Confirmed
        } else {
            Outcome::Refused
        };
        self.set(protection, outcome, process_wide);
    }

    /// Records an option: confirmed when it reads back, whoever asked for it; else refused when
    /// this call asked, and not requested when it did not.
    #[cfg(any(target_os = "linux", target_os = "android", windows, test))]
    pub(crate) fn option(
        &mut self,
        protection: Protection,
        asked: bool,
        holds: bool,
        process_wide: bool,
    ) {
        let outcome = match (holds, asked) {
            (true, _) => Outcome::Confirmed,
            (false, true) => Outcome::Refused,
            (false, false) => Outcome::NotRequested,
        };
        self.set(protection, outcome, process_wide);
    }

    /// The answer, whose fields are true exactly for the confirmed protections.
    pub(crate) fn finish(self) -> Isolation {
        let has = |protection: Protection| self.outcomes[protection.index()] == Outcome::Confirmed;
        Isolation {
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
            signals_to_self_only: has(Protection::SignalsToSelfOnly),
            signals_within_layer: has(Protection::SignalsWithinLayer),
            memory_locked: has(Protection::MemoryLocked),
            no_new_programs: has(Protection::NoNewPrograms),
            no_planted_libraries: has(Protection::NoPlantedLibraries),
            desktop_restricted: has(Protection::DesktopRestricted),
            low_integrity: has(Protection::LowIntegrity),
            folder_writes: has(Protection::FolderWrites),
            outcomes: self.outcomes,
            process_wide: self.process_wide,
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
    /// What became of it in the call.
    pub outcome: Outcome,
    /// How far it reaches, when it is in effect.
    pub reach: Reach,
    /// What the call observed for this outcome, in words.
    pub evidence: &'static str,
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
    fn a_thread_scoped_protection_fails_the_process_wide_rule() {
        let mut findings = Findings::new();
        findings.set(Protection::WholeProcess, Outcome::Confirmed, true);
        findings.set(Protection::NoNewSockets, Outcome::Confirmed, false);
        let isolation = findings.finish();
        assert!(isolation.require(&[Protection::NoNewSockets]).is_ok());
        let refused = isolation
            .require_process_wide(&[Protection::NoNewSockets])
            .unwrap_err();
        assert_eq!(refused.missing, [Protection::NoNewSockets]);
        let mut findings = Findings::new();
        findings.set(Protection::NoNewSockets, Outcome::Confirmed, true);
        let refused = findings
            .finish()
            .require_process_wide(&[Protection::NoNewSockets, Protection::NoFileChanges])
            .unwrap_err();
        assert!(refused.missing.contains(&Protection::WholeProcess));
        assert!(refused.missing.contains(&Protection::NoFileChanges));
        assert!(!refused.missing.contains(&Protection::NoNewSockets));
    }

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
        // It says of its pages what a secret made the same way says.
        let open = Secret::with_capacity(32);
        assert!(!secret.is_empty() && secret.is_locked() == open.is_locked());
        assert_eq!(secret.is_out_of_dumps(), open.is_out_of_dumps());
        assert_eq!(secret.is_out_of_children(), open.is_out_of_children());
    }

    /// A strict work area is given only locked. A page lies within every lock limit a system sets
    /// by default; a sanitizer's own `mlock` locks nothing, and then it is refused.
    #[test]
    fn a_strict_work_area_is_given_only_locked() {
        let strict = WorkArea::locked(4096);
        let refused = strict.as_ref().err() == Some(&SecretError::NotLocked);
        assert!(strict.as_ref().is_ok_and(WorkArea::is_locked) || refused);
    }

    /// Two pages of the largest size in use, 64 KiB: Linux touches every page before handing it
    /// out, and that must leave no trace.
    #[test]
    fn a_zeroed_secret_holds_only_zeros_on_every_page() {
        let secret = Secret::zeroed(128 << 10);
        assert!(secret.as_bytes().iter().all(|&byte| byte == 0));
    }

    /// More than any system gives: the work area is refused, and the program goes on.
    #[test]
    fn a_work_area_beyond_the_system_is_refused() {
        for bytes in [usize::MAX, usize::MAX / 2 + 4096] {
            assert!(WorkArea::new(bytes).is_none(), "{bytes}");
            assert_eq!(WorkArea::locked(bytes).err(), Some(SecretError::NoMemory));
        }
    }

    /// Every protection has a measure whose words fit its outcome, and the answer survives the
    /// bytes a worker sends.
    #[test]
    fn measures_say_what_was_observed_and_survive_the_handshake() {
        let mut findings = Findings::new();
        findings.check(Protection::NoCoreDumps, true, true);
        findings.check(Protection::NoNewSockets, false, false);
        findings.option(Protection::MemoryLocked, false, false, true);
        findings.set(Protection::SpeculationLimited, Outcome::Unknown, false);
        let isolation = findings.finish();
        assert!(isolation.no_core_dumps && !isolation.no_new_sockets && !isolation.memory_locked);
        let measures = isolation.measures();
        assert_eq!(measures.len(), Protection::ALL.len());
        for measure in &measures {
            assert_eq!(measure.outcome, isolation.outcome(measure.protection));
            assert!(!measure.evidence.is_empty());
        }
        let of = |protection: Protection| {
            measures
                .iter()
                .find(|measure| measure.protection == protection)
                .unwrap()
        };
        // An option that was not asked for never claims that a call was accepted.
        assert_eq!(of(Protection::MemoryLocked).outcome, Outcome::NotRequested);
        assert_eq!(
            of(Protection::MemoryLocked).evidence,
            "the call did not ask for it"
        );
        assert_eq!(of(Protection::NoCoreDumps).reach, Reach::Process);
        assert_eq!(of(Protection::NoNewSockets).reach, Reach::Thread);
        assert_eq!(of(Protection::EmptyNetwork).outcome, Outcome::Unsupported);
        assert_eq!(
            Isolation::from_bytes(&isolation.to_bytes()),
            Some(isolation)
        );
        assert_eq!(Isolation::from_bytes(&[0; 3]), None);
        // A byte is taken only when it names an outcome and a reach, and comes back as it was.
        for value in 0..=u8::MAX {
            let mut bytes = isolation.to_bytes();
            bytes[3] = value;
            let read = Isolation::from_bytes(&bytes);
            assert_eq!(read.is_some(), value & 7 <= 4 && value < 16, "{value}");
            assert!(read.is_none_or(|read| read.to_bytes() == bytes), "{value}");
        }
        // Only a confirmed protection passes the strict mode.
        let missing = isolation
            .require(&[Protection::NoCoreDumps, Protection::SpeculationLimited])
            .unwrap_err();
        assert_eq!(missing.missing, [Protection::SpeculationLimited]);
    }

    #[test]
    fn debug_output_hides_the_bytes() {
        let mut secret = Secret::with_capacity(8);
        secret.push(b"public").unwrap();
        assert_eq!(format!("{secret:?}"), "Secret(hidden)");
        let mut area = WorkArea::new(8).unwrap();
        area.as_mut_slice().copy_from_slice(b"public!!");
        assert_eq!(format!("{area:?}"), "WorkArea(8 bytes, hidden)");
    }

    /// Each refusal of a buffer says which it was, the room of a full one included.
    #[test]
    fn a_refused_buffer_says_why() {
        let full = SecretError::Full { capacity: 16 }.to_string();
        assert!(full.contains("16"), "{full}");
        let texts = [
            full,
            SecretError::NotLocked.to_string(),
            SecretError::NoMemory.to_string(),
        ];
        let unique: std::collections::BTreeSet<&String> = texts.iter().collect();
        assert_eq!(unique.len(), texts.len(), "{texts:?}");
    }
}
