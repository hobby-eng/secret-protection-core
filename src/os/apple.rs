//! macOS attempts debugger restrictions and a sandbox with limited terminal and `/dev/null`
//! writes. Both macOS and iOS check the process core-dump limit.
#![allow(
    unsafe_code,
    reason = "sysctl, ptrace and sandbox_init are foreign functions"
)]

use crate::protect::{Findings, Isolation, Options};
use crate::{Outcome, Protection};

/// The options of [`Options`] are for Linux, Android and Windows: none applies here.
pub(crate) fn enter(_options: Options) -> Isolation {
    let mut found = Findings::new();
    found.check(
        Protection::NoCoreDumps,
        super::unix::forbid_core_dumps(),
        true,
    );
    #[cfg(target_os = "macos")]
    {
        // Before the sandbox, which may not allow the call.
        let reading = macos::refuse_debuggers();
        let (sockets, files) = macos::enter_sandbox();
        found.set(Protection::NoMemoryReading, reading, true);
        found.set(Protection::NoNewSockets, sockets, true);
        found.set(Protection::NoFileChanges, files, true);
        // The profile allows neither a new program nor a fork; no probe confirms it yet.
        let programs = if macos::entered() {
            Outcome::Unknown
        } else {
            Outcome::Refused
        };
        found.set(Protection::NoNewPrograms, programs, true);
    }
    found.check(Protection::WholeProcess, true, true);
    found.finish()
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::net::{Ipv4Addr, UdpSocket};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::Outcome;

    unsafe extern "C" {
        fn sandbox_init(
            profile: *const libc::c_char,
            flags: u64,
            error: *mut *mut libc::c_char,
        ) -> libc::c_int;
        fn sandbox_free_error(error: *mut libc::c_char);
    }

    /// The sandbox refuses everything except reading files, the terminal and /dev/null, the process
    /// itself, reading system settings and loading system libraries. That shuts the network, file
    /// writes, the system's services (clipboard, opening URLs, preferences) and signals to others.
    const PROFILE: &std::ffi::CStr = c"(version 1)(deny default)\
        (allow file-read*)\
        (allow file-write* (literal \"/dev/null\") (literal \"/dev/tty\") \
        (regex #\"^/dev/ttys[0-9]+$\"))\
        (allow file-ioctl (literal \"/dev/tty\") (regex #\"^/dev/ttys[0-9]+$\"))\
        (allow signal (target self))\
        (allow process-info* (target self))\
        (allow sysctl-read)\
        (allow file-map-executable (subpath \"/usr/lib\") (subpath \"/System\"))";
    /// P_TRACED of sys/proc.h, as `kern.proc.pid` reports it in `kp_proc.p_flag`.
    const TRACED: i32 = 0x0000_0800;

    /// Refuses a debugger from now on (`PT_DENY_ATTACH`). A process that a debugger already traces
    /// would end at the call, so it is left as it is, and reads as refused. No public call reads
    /// the refusal back: the kernel's answer stands for it.
    pub(super) fn refuse_debuggers() -> Outcome {
        match traced() {
            None => Outcome::Unknown,
            Some(true) => Outcome::Refused,
            Some(false) => {
                // SAFETY: PT_DENY_ATTACH takes no process, address or data and touches no memory.
                let denied =
                    unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, ptr::null_mut(), 0) } == 0;
                if denied {
                    Outcome::Confirmed
                } else {
                    Outcome::Refused
                }
            }
        }
    }

    /// Whether a debugger traces this process, as `kern.proc.pid` reports it.
    fn traced() -> Option<bool> {
        /// The size of `struct kinfo_proc` (sys/sysctl.h) on a 64-bit system, and the offset of
        /// `kp_proc.p_flag` in it (sys/proc.h), after a 16-byte union and two pointers.
        const KINFO_PROC_BYTES: usize = 648;
        const FLAG: usize = 32;
        let pid = libc::c_int::try_from(std::process::id()).ok()?;
        let mut name = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        let mut info = [0u8; KINFO_PROC_BYTES];
        let mut size = info.len();
        // SAFETY: sysctl reads the four parts of the name and writes at most `size` bytes into
        // `info` and their number into `size`, all of which live for the call.
        let read = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                4,
                info.as_mut_ptr().cast(),
                &mut size,
                ptr::null_mut(),
                0,
            )
        } == 0;
        let flags =
            i32::from_ne_bytes([info[FLAG], info[FLAG + 1], info[FLAG + 2], info[FLAG + 3]]);
        (read && size == KINFO_PROC_BYTES).then_some(flags & TRACED != 0)
    }

    /// Whether this crate's profile went in, in this process or one it was forked from: the
    /// sandbox is inherited, and a second profile is refused.
    static ENTERED: AtomicBool = AtomicBool::new(false);

    /// Whether this crate's profile is in place.
    pub(super) fn entered() -> bool {
        ENTERED.load(Ordering::Relaxed)
    }

    /// Enters the sandbox, for the whole process and for good, and returns what became of the
    /// network and of file writes. A refusal read back without this crate's profile in place may
    /// come from the folder or from another sandbox, which says nothing of the rest: unknown.
    pub(super) fn enter_sandbox() -> (Outcome, Outcome) {
        // One call at a time: of two at once the second is refused, and must still find the
        // first one's success.
        static ENTERING: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _entering = ENTERING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !ENTERED.load(Ordering::Relaxed) {
            let mut error = ptr::null_mut();
            // SAFETY: the profile is a NUL-terminated text; on a failure the call allocates a
            // message into `error`, freed below.
            let entered = unsafe { sandbox_init(PROFILE.as_ptr(), 0, &mut error) } == 0;
            if !error.is_null() {
                // SAFETY: frees the message sandbox_init allocated, once.
                unsafe { sandbox_free_error(error) };
            }
            // Never back to false: a profile that went in stays in.
            ENTERED.fetch_or(entered, Ordering::Relaxed);
        }
        let outcome = |refused: bool| match (ENTERED.load(Ordering::Relaxed), refused) {
            (true, true) => Outcome::Confirmed,
            (false, true) => Outcome::Unknown,
            (_, false) => Outcome::Refused,
        };
        (outcome(network_refused()), outcome(file_writes_refused()))
    }

    /// Probes exclusive creation in the temporary directory. An existing file is never opened
    /// or truncated. After successful creation, cleanup attempts to unlink the probe path.
    fn file_writes_refused() -> bool {
        let path =
            std::env::temp_dir().join(format!("secret-protection-core-{}", std::process::id()));
        let made = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path);
        match made {
            Ok(_) => {
                let _ = std::fs::remove_file(&path);
                false
            }
            Err(error) => error.kind() == io::ErrorKind::PermissionDenied,
        }
    }

    /// Whether the sandbox refuses to bind or connect a UDP socket on the loopback address, which
    /// sends nothing; a refusal for another reason does not count.
    fn network_refused() -> bool {
        let refused = |error: io::Error| error.raw_os_error() == Some(libc::EPERM);
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
            Err(error) => refused(error),
            // The discard port: nothing would answer even with a network.
            Ok(socket) => socket.connect((Ipv4Addr::LOCALHOST, 9)).is_err_and(refused),
        }
    }
}

/// What a call observed for `protection` when it reports `outcome`, in words.
pub(crate) fn evidence(protection: Protection, outcome: Outcome) -> Option<&'static str> {
    use {Outcome as O, Protection as P};
    Some(match (protection, outcome) {
        (P::NoCoreDumps, O::Confirmed) => "RLIMIT_CORE reads back 0",
        (P::NoCoreDumps, O::Refused) => "RLIMIT_CORE did not read back 0",
        (P::NoMemoryReading, O::Confirmed) => "PT_DENY_ATTACH accepted, with no debugger attached",
        (P::NoMemoryReading, O::Refused) => "a debugger is attached, or PT_DENY_ATTACH was refused",
        (P::NoMemoryReading, O::Unknown) => "the process could not be asked whether it is traced",
        (P::NoNewPrograms, O::Unknown) => "the sandbox profile allows no new program; not probed",
        (P::NoNewPrograms, O::Refused) => "the sandbox was not entered",
        (P::NoNewSockets, O::Confirmed) => {
            "this crate's sandbox is in, and a UDP socket was refused"
        }
        (P::NoNewSockets, O::Refused) => "a UDP socket was not refused",
        (P::NoNewSockets, O::Unknown) => {
            "a UDP socket was refused, but this crate's sandbox profile is not in"
        }
        (P::NoFileChanges, O::Confirmed) => {
            "this crate's sandbox is in, and a new file was refused"
        }
        (P::NoFileChanges, O::Refused) => "a new file was not refused",
        (P::NoFileChanges, O::Unknown) => {
            "a new file was refused, but this crate's sandbox profile is not in"
        }
        (P::WholeProcess, O::Confirmed) => "this platform applies isolation at process scope",
        _ => return None,
    })
}
