//! [`Options`], the protections a program turns on itself; [`Protection`] and [`Outcome`], what
//! [`super::Isolation`] says of each; and [`Missing`], the refusal of the strict mode.

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

    /// Linux and Android: refuses file locks (`flock`, the lock commands of `fcntl`, and leases
    /// and delegations), which another program of the user sees and which could carry a secret
    /// out one bit at a time. A database such as SQLite takes a lock to read, and fails without
    /// one.
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

    /// Windows: from now on only DLLs signed by Microsoft load (`ProcessSignaturePolicy`), so that
    /// no other program's DLL gets in. The program's own DLLs loaded later, graphics drivers and
    /// many input methods fail to load.
    #[must_use]
    pub const fn microsoft_signed_only(mut self) -> Self {
        self.microsoft_signed = true;
        self
    }

    /// Linux and Android: signals go only to this process itself, by a filter rule that names its
    /// process number. It is for a process that forks no more: a child made by `fork` afterwards
    /// inherits the rule with its parent's number, and reports the protection as missing.
    ///
    /// The rule also refuses the `fcntl` owner commands and setting `O_ASYNC`, so signal-driven
    /// I/O fails, even to the process itself, and so does setting other flags with `F_SETFL` on a
    /// descriptor that already has `O_ASYNC`. Job-control signals that the kernel sends to the
    /// whole process group stay outside it: a process that keeps a controlling terminal from a
    /// background group gets SIGTTIN or SIGTTOU for its group when it reads the terminal, changes
    /// its settings, or writes to it under `TOSTOP`. A worker has no controlling terminal.
    #[must_use]
    pub const fn signals_to_self_only(mut self) -> Self {
        self.own_signals = true;
        self
    }

    /// Requests Linux or Android `mlockall` for current and future mappings. Check
    /// [`Isolation::memory_locked`]. The lock quota can prevent success. Unlocking memory later
    /// can leave the crate's record of an earlier successful lock in place.
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
    /// [`Isolation::signals_to_self_only`].
    SignalsToSelfOnly,
    /// [`Isolation::signals_within_layer`].
    SignalsWithinLayer,
    /// [`Isolation::memory_locked`].
    MemoryLocked,
    /// [`Isolation::no_new_programs`].
    NoNewPrograms,
    /// [`Isolation::no_planted_libraries`].
    NoPlantedLibraries,
    /// [`Isolation::desktop_restricted`].
    DesktopRestricted,
    /// [`Isolation::low_integrity`].
    LowIntegrity,
    /// [`Isolation::folder_writes`].
    FolderWrites,
}

impl Protection {
    /// How many protections there are.
    pub(crate) const COUNT: usize = 19;

    /// Every protection, in the order of the fields of [`Isolation`].
    pub const ALL: [Self; Self::COUNT] = [
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
        Self::SignalsToSelfOnly,
        Self::SignalsWithinLayer,
        Self::MemoryLocked,
        Self::NoNewPrograms,
        Self::NoPlantedLibraries,
        Self::DesktopRestricted,
        Self::LowIntegrity,
        Self::FolderWrites,
    ];

    /// Its place in [`Protection::ALL`].
    pub(crate) const fn index(self) -> usize {
        self as usize
    }

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
            Self::SignalsToSelfOnly => "signals only to the process itself",
            Self::SignalsWithinLayer => "signals only inside the Landlock layer",
            Self::MemoryLocked => "the whole process out of swap",
            Self::NoNewPrograms => "no other program started",
            Self::NoPlantedLibraries => "no planted libraries",
            Self::DesktopRestricted => "no writing to the clipboard or to other windows",
            Self::LowIntegrity => "low integrity",
            Self::FolderWrites => "writes only beneath the granted folders",
        }
    }
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What became of one protection in a call of [`Isolation::enter`]. Only [`Outcome::Confirmed`]
/// counts as holding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// In effect, and the call observed it.
    Confirmed,
    /// The attempt or its check failed.
    Refused,
    /// The call did not request this option and did not confirm it was already active.
    NotRequested,
    /// Not offered on this system.
    #[default]
    Unsupported,
    /// It may be in effect, but the call could not confirm it.
    Unknown,
}

impl Outcome {
    /// Every outcome, in the order of the numbers a worker sends.
    const ALL: [Self; 5] = [
        Self::Confirmed,
        Self::Refused,
        Self::NotRequested,
        Self::Unsupported,
        Self::Unknown,
    ];

    /// The number a worker sends for it.
    pub(crate) const fn to_bits(self) -> u8 {
        self as u8
    }

    /// The outcome of a number that [`Outcome::to_bits`] made.
    pub(crate) fn from_bits(bits: u8) -> Option<Self> {
        Self::ALL.get(usize::from(bits)).copied()
    }
}

/// A required protection lacked confirmation in the required scope. The caller receives
/// the isolation report and can stop before reading a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Missing {
    /// The required protections that lacked confirmation, in the order of [`Protection::ALL`].
    pub missing: Vec<Protection>,
    /// What reads back as holding.
    pub isolation: Isolation,
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("required protections not confirmed in scope:")?;
        for (index, protection) in self.missing.iter().enumerate() {
            let separator = if index == 0 { " " } else { ", " };
            write!(f, "{separator}{protection}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Missing {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Options cross to a worker as bits: each builder sets a bit of its own, and every set of
    /// options comes back from its bits.
    #[test]
    fn every_option_crosses_to_a_worker_as_its_own_bit() {
        let each = [
            Options::new().refuse_file_locks(),
            Options::new().refuse_sendmsg(),
            Options::new().refuse_dynamic_code(),
            Options::new().microsoft_signed_only(),
            Options::new().signals_to_self_only(),
            Options::new().lock_all_memory(),
        ];
        let bits: Vec<u32> = each.iter().map(|options| options.to_bits()).collect();
        assert!(bits.iter().all(|bits| bits.count_ones() == 1));
        assert_eq!(bits.iter().fold(0, |all, bits| all | bits), 0b11_1111);
        for set in 0..64 {
            assert_eq!(Options::from_bits(set).to_bits(), set);
        }
    }

    /// A refusal of the strict mode names each protection that does not hold, each by a name of
    /// its own, and no outcome is explained by an empty text or by the text of another.
    #[test]
    fn a_refusal_names_what_is_missing_and_why() {
        let names: Vec<String> = Protection::ALL.iter().map(ToString::to_string).collect();
        let unique: std::collections::BTreeSet<&String> = names.iter().collect();
        assert!(names.iter().all(|name| !name.is_empty()) && unique.len() == names.len());
        let missing = Missing {
            missing: vec![Protection::NoCoreDumps, Protection::LowIntegrity],
            isolation: Isolation::default(),
        };
        let text = missing.to_string();
        assert_eq!(
            text,
            "required protections not confirmed in scope: no core dumps, low integrity"
        );
        // What this system says of a protection that holds and of one refused differs; some, such
        // as a whole process on Windows, it never refuses.
        for protection in Protection::ALL {
            let held = crate::os::evidence(protection, Outcome::Confirmed);
            let refused = crate::os::evidence(protection, Outcome::Refused);
            assert!(held.is_none() || held != refused, "{protection}");
            for outcome in Outcome::ALL {
                let said = crate::os::evidence(protection, outcome);
                assert!(said.is_none_or(|said| !said.is_empty()));
            }
        }
    }

    #[test]
    fn protections_and_outcomes_keep_their_numbers() {
        for (index, protection) in Protection::ALL.into_iter().enumerate() {
            assert_eq!(protection.index(), index);
        }
        for outcome in Outcome::ALL {
            assert_eq!(Outcome::from_bits(outcome.to_bits()), Some(outcome));
        }
        assert_eq!(Outcome::from_bits(5), None);
        let options = Options::new().signals_to_self_only().refuse_sendmsg();
        assert_eq!(Options::from_bits(options.to_bits()), options);
    }
}
