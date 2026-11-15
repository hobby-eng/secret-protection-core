//! [`Options`], the protections of [`super::Isolation`] that a program turns on itself, and the
//! strict mode: [`Protection`], one confirmed protection, and [`Missing`], the protections a
//! program required and did not get.

use std::fmt;

use super::Isolation;

/// Protections that can break some programs, so they stay off until the program turns them on.
/// Each applies only on its systems and shows up in a field of [`Isolation`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub(crate) file_locks: bool,
    pub(crate) sendmsg: bool,
    pub(crate) dynamic_code: bool,
    pub(crate) microsoft_signed: bool,
    pub(crate) own_signals: bool,
    pub(crate) lock_all: bool,
}

impl Options {
    /// No option: what [`Isolation::enter`] applies.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            file_locks: false,
            sendmsg: false,
            dynamic_code: false,
            microsoft_signed: false,
            own_signals: false,
            lock_all: false,
        }
    }

    /// Linux and Android: refuses file locks (`flock` and the lock commands of `fcntl`), which
    /// another program of the user sees and which could carry a secret out one bit at a time. A
    /// database such as SQLite takes a lock to read, and fails without one.
    #[must_use]
    pub const fn refuse_file_locks(mut self) -> Self {
        self.file_locks = true;
        self
    }

    /// Linux and Android: refuses `sendmsg`, through which a socket opened before could send to an
    /// address the filter cannot read. Wayland, D-Bus and every program that passes descriptors
    /// sends with it, and fails without it.
    #[must_use]
    pub const fn refuse_sendmsg(mut self) -> Self {
        self.sendmsg = true;
        self
    }

    /// Windows: no new executable code (`ProcessDynamicCodePolicy`): memory can neither be made
    /// executable nor changed once it is, so code written at run time, by a just-in-time compiler
    /// or by an attacker, cannot run. A web view, or any runtime with such a compiler, fails.
    #[must_use]
    pub const fn refuse_dynamic_code(mut self) -> Self {
        self.dynamic_code = true;
        self
    }

    /// Linux and Android: signals go only to this process itself. Landlock already blocks signals
    /// to other processes from Linux 6.12; this covers older kernels and Android. Children started
    /// afterwards can't be signalled either, nor signal themselves with `kill`.
    #[must_use]
    pub const fn signals_to_self_only(mut self) -> Self {
        self.own_signals = true;
        self
    }

    /// Linux and Android: every page of the process, now and later, stays out of swap
    /// (`mlockall`), so copies the program makes of a secret never reach the disk either. Works
    /// only when the lock limit covers the whole process, which usually takes raising it; under
    /// the default limit the call is refused and [`Isolation::memory_locked`] says so.
    #[must_use]
    pub const fn lock_all_memory(mut self) -> Self {
        self.lock_all = true;
        self
    }

    /// One bit for each option, as a worker gets them from its parent.
    pub(crate) fn to_bits(self) -> u32 {
        u32::from(self.file_locks)
            | u32::from(self.sendmsg) << 1
            | u32::from(self.dynamic_code) << 2
            | u32::from(self.microsoft_signed) << 3
            | u32::from(self.own_signals) << 4
            | u32::from(self.lock_all) << 5
    }

    /// The options that [`Options::to_bits`] made.
    pub(crate) fn from_bits(bits: u32) -> Self {
        Self {
            file_locks: bits & 1 != 0,
            sendmsg: bits & 2 != 0,
            dynamic_code: bits & 4 != 0,
            microsoft_signed: bits & 8 != 0,
            own_signals: bits & 16 != 0,
            lock_all: bits & 32 != 0,
        }
    }

    /// Windows: from now on only DLLs signed by Microsoft load (`ProcessSignaturePolicy`), so that
    /// no other program's DLL gets in. The program's own DLLs loaded later, graphics drivers and
    /// many input methods fail to load.
    #[must_use]
    pub const fn microsoft_signed_only(mut self) -> Self {
        self.microsoft_signed = true;
        self
    }
}

/// One protection that [`Isolation`] reports, for a program to require it: each names the field
/// of the same meaning.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protection {
    /// [`Isolation::no_core_dumps`].
    NoCoreDumps,
    /// [`Isolation::no_memory_reading`].
    NoMemoryReading,
    /// [`Isolation::no_new_sockets`].
    NoNewSockets,
    /// [`Isolation::empty_network`].
    EmptyNetwork,
    /// [`Isolation::no_file_changes`].
    NoFileChanges,
    /// [`Isolation::speculation_limited`].
    SpeculationLimited,
    /// [`Isolation::whole_process`].
    WholeProcess,
    /// [`Isolation::file_locks_refused`].
    FileLocksRefused,
    /// [`Isolation::sendmsg_refused`].
    SendmsgRefused,
    /// [`Isolation::dynamic_code_refused`].
    DynamicCodeRefused,
    /// [`Isolation::microsoft_signed_only`].
    MicrosoftSignedOnly,
    /// [`Isolation::foreign_signals_refused`].
    ForeignSignalsRefused,
    /// [`Isolation::memory_locked`].
    MemoryLocked,
}

impl Protection {
    /// Every protection, in the order of the fields of [`Isolation`].
    pub const ALL: [Self; 13] = [
        Self::NoCoreDumps,
        Self::NoMemoryReading,
        Self::NoNewSockets,
        Self::EmptyNetwork,
        Self::NoFileChanges,
        Self::SpeculationLimited,
        Self::WholeProcess,
        Self::FileLocksRefused,
        Self::SendmsgRefused,
        Self::DynamicCodeRefused,
        Self::MicrosoftSignedOnly,
        Self::ForeignSignalsRefused,
        Self::MemoryLocked,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::NoCoreDumps => "no core dumps",
            Self::NoMemoryReading => "no reading of the memory",
            Self::NoNewSockets => "no new sockets",
            Self::EmptyNetwork => "an empty network",
            Self::NoFileChanges => "no file changes",
            Self::SpeculationLimited => "speculation limited",
            Self::WholeProcess => "the whole process",
            Self::FileLocksRefused => "file locks refused",
            Self::SendmsgRefused => "sendmsg refused",
            Self::DynamicCodeRefused => "no new executable code",
            Self::MicrosoftSignedOnly => "only DLLs signed by Microsoft",
            Self::ForeignSignalsRefused => "no signals to other processes",
            Self::MemoryLocked => "the whole process out of swap",
        }
    }
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The protections a program required that did not read back, with everything that did: the
/// error of [`Isolation::enter_requiring`] and [`crate::Worker::start`]. What was applied stays
/// applied, for good: the program stops before it reads a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Missing {
    /// The required protections that do not hold, in the order of [`Protection::ALL`].
    pub missing: Vec<Protection>,
    /// What reads back as holding.
    pub isolation: Isolation,
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("required protections do not hold:")?;
        for (index, protection) in self.missing.iter().enumerate() {
            let separator = if index == 0 { " " } else { ", " };
            write!(f, "{separator}{protection}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Missing {}
