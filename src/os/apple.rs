//! macOS attempts debugger restrictions and a sandbox that writes only to `/dev/null` and the
//! process's own terminal. Both macOS and iOS check the process core-dump limit.
#![allow(
    unsafe_code,
    reason = "sysctl, ptrace and sandbox_init are foreign functions"
)]

use crate::protect::{Findings, Isolation, Options};
use crate::{Outcome, Protection};

/// The options of [`Options`] are for Linux, Android and Windows: none applies here. `folders`
/// go into the macOS sandbox, which then lets writes through beneath them.
pub(crate) fn enter_granting(_options: Options, folders: &[&crate::WritableFolder]) -> Isolation {
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
        let paths = macos::folder_paths(folders);
        let (sockets, files, granted) = macos::enter_sandbox(paths.as_deref().unwrap_or_default());
        let writes = match (folders.is_empty(), granted) {
            (true, _) => Outcome::NotRequested,
            (false, true) => Outcome::Confirmed,
            (false, false) => Outcome::Refused,
        };
        found.set(Protection::FolderWrites, writes, true);
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
    #[cfg(not(target_os = "macos"))]
    let _ = folders;
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

    /// The sandbox refuses everything except reading files other than terminal devices (a name
    /// under /dev starting with tty, pty, cu. or console), `/dev/null`,
    /// the process's own terminal, the process itself, reading system settings and loading system
    /// libraries. That shuts the network, file writes, the system's services (clipboard, opening
    /// URLs, preferences), signals to others and the user's other terminals.
    ///
    /// The own terminal, named by path from the standard streams, gets data writes and ioctls,
    /// not mode or owner changes. The sandbox cannot tell one ioctl from another, so through a
    /// controlling terminal it also admits TIOCSTI, input the shell reads as the user's: a worker
    /// has none (`setsid`).
    fn profile(folders: &[String]) -> Option<std::ffi::CString> {
        let terminals = own_terminals();
        let own: String = terminals
            .iter()
            .map(|path| format!(" (literal \"{path}\")"))
            .collect();
        // The terminal rules, for a program on a terminal only: one whose streams go elsewhere gets
        // none, so no TIOCSTI through /dev/tty either. A rule without a path would allow everything.
        let (read_own, tty, ioctl) = if terminals.is_empty() {
            (String::new(), "", String::new())
        } else {
            let tty = " (literal \"/dev/tty\")";
            (
                format!("(allow file-read*{tty}{own})"),
                tty,
                format!("(allow file-ioctl{tty}{own})"),
            )
        };
        // Beneath a granted folder: new regular files and folders only (no links, FIFOs or
        // devices), data, and removal of what is beneath, not of the folder itself; no modes,
        // owners, times or extended attributes. The sandbox cannot tell a new file from an old
        // one, so files there can be written again.
        let writes: String = folders
            .iter()
            .map(|path| {
                format!(
                    "(allow file-write-create (require-all (subpath \"{path}\") \
                     (require-any (vnode-type REGULAR-FILE) (vnode-type DIRECTORY))))\
                     (allow file-write-data (subpath \"{path}\"))\
                     (allow file-write-unlink (require-all (subpath \"{path}\") \
                     (require-not (literal \"{path}\"))))"
                )
            })
            .collect();
        let text = format!(
            "(version 1)(deny default)\
             (allow file-read* (require-not (regex #\"^/dev/(tty|pty|cu[.]|console)\"))){read_own}\
             (allow file-write-data (literal \"/dev/null\"){tty}{own}){ioctl}\
             (allow signal (target self))\
             (allow process-info* (target self))\
             (allow sysctl-read)\
             (allow file-map-executable (subpath \"/usr/lib\") (subpath \"/System\")){writes}"
        );
        std::ffi::CString::new(text).ok()
    }

    /// The terminals among the standard streams, by path; only plain device names, which the
    /// profile's text can hold as they are.
    fn own_terminals() -> Vec<String> {
        let mut found = Vec::new();
        for stream in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            let mut name = [0 as libc::c_char; 128];
            // SAFETY: ttyname_r writes a NUL-terminated name of at most the buffer's length.
            if unsafe { libc::ttyname_r(stream, name.as_mut_ptr(), name.len()) } != 0 {
                continue;
            }
            // SAFETY: the call above wrote a NUL-terminated name into `name`.
            let path = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
            let path = path.to_string_lossy().into_owned();
            let plain = path.strip_prefix("/dev/").is_some_and(|rest| {
                !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric())
            });
            if plain && !found.contains(&path) {
                found.push(path);
            }
        }
        found
    }
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

    /// PROC_PIDREGIONINFO and struct proc_regioninfo of sys/proc_info.h, which libc lacks.
    const PROC_PIDREGIONINFO: libc::c_int = 7;
    #[repr(C)]
    struct RegionInfo {
        protection: u32,
        max_protection: u32,
        inheritance: u32,
        flags: u32,
        offset: u64,
        behavior: u32,
        user_wired_count: u32,
        user_tag: u32,
        pages_resident: u32,
        pages_shared_now_private: u32,
        pages_swapped_out: u32,
        pages_dirtied: u32,
        ref_count: u32,
        shadow_depth: u32,
        share_mode: u32,
        private_pages_resident: u32,
        shared_pages_resident: u32,
        obj_id: u32,
        depth: u32,
        address: u64,
        size: u64,
    }
    /// PROC_REGION_SUBMAP of sys/proc_info.h.
    const PROC_REGION_SUBMAP: u32 = 1;
    /// SM_SHARED, SM_TRUESHARED and SM_SHARED_ALIASED of mach/vm_region.h.
    const SHARED_MODES: [u32; 3] = [4, 5, 7];

    pub(super) fn shared_mappings() -> Option<Vec<crate::SharedMapping>> {
        let size = libc::c_int::try_from(std::mem::size_of::<RegionInfo>()).ok()?;
        // SAFETY: getpid takes nothing and only answers.
        let pid = unsafe { libc::getpid() };
        let heap = Box::new(0u8);
        let landmarks = [
            shared_mappings as *const () as usize as u64,
            &raw const size as usize as u64,
            &raw const *heap as usize as u64,
        ];
        let mut seen = [false; 3];
        let mut found = Vec::new();
        let mut address = 0u64;
        loop {
            let mut info = std::mem::MaybeUninit::<RegionInfo>::zeroed();
            // SAFETY: the call writes at most `size` bytes, the size of the struct given.
            let got = unsafe {
                libc::proc_pidinfo(
                    pid,
                    PROC_PIDREGIONINFO,
                    address,
                    info.as_mut_ptr().cast(),
                    size,
                )
            };
            if got == 0 {
                break;
            }
            if got != size {
                return None;
            }
            // SAFETY: zeroed, then filled whole by the call that returned its size.
            let info = unsafe { info.assume_init() };
            let end = info.address.checked_add(info.size)?;
            for (landmark, seen) in landmarks.iter().zip(&mut seen) {
                *seen |= (info.address..end).contains(landmark);
            }
            // A MAP_SHARED region that this process alone maps reads as private, but keeps
            // VM_INHERIT_SHARE, which mmap gives it. A submap, as the system's shared library
            // cache is mapped, is no mapping of the program's (PROC_REGION_SUBMAP).
            let shared = SHARED_MODES.contains(&info.share_mode)
                || info.inheritance == libc::VM_INHERIT_SHARE as u32;
            let shared = shared && info.flags & PROC_REGION_SUBMAP == 0;
            if shared && info.max_protection & libc::VM_PROT_WRITE as u32 != 0 {
                found.push(crate::SharedMapping {
                    start: usize::try_from(info.address).ok()?,
                    length: usize::try_from(info.size).ok()?,
                    name: region_name(pid, info.address),
                });
            }
            if end <= address {
                return None;
            }
            address = end;
        }
        drop(heap);
        seen.iter().all(|&seen| seen).then_some(found)
    }

    /// The path of the file a region maps, or nothing.
    fn region_name(pid: libc::c_int, address: u64) -> String {
        let mut name = [0u8; libc::PATH_MAX as usize];
        // SAFETY: the call writes at most the buffer's length into it.
        let length = unsafe {
            libc::proc_regionfilename(pid, address, name.as_mut_ptr().cast(), name.len() as u32)
        };
        let length = usize::try_from(length).unwrap_or(0).min(name.len());
        String::from_utf8_lossy(&name[..length]).into_owned()
    }

    /// The real paths of `folders`, for the profile, or `None` when one is no longer the new,
    /// empty folder made, or its path holds a character the profile's text cannot.
    pub(super) fn folder_paths(folders: &[&crate::WritableFolder]) -> Option<Vec<String>> {
        use std::os::fd::AsRawFd;
        folders
            .iter()
            .map(|folder| {
                if !folder.still_new() {
                    return None;
                }
                let mut path = [0 as libc::c_char; libc::PATH_MAX as usize];
                // SAFETY: F_GETPATH writes a NUL-terminated path of at most PATH_MAX bytes.
                if unsafe { libc::fcntl(folder.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) }
                    == -1
                {
                    return None;
                }
                // SAFETY: the call above wrote a NUL-terminated path into `path`.
                let path = unsafe { std::ffi::CStr::from_ptr(path.as_ptr()) };
                let path = path.to_str().ok()?;
                (path.starts_with('/') && !path.contains(['"', '\\'])).then(|| path.to_owned())
            })
            .collect()
    }

    /// Enters the sandbox, for the whole process and for good, and returns what became of the
    /// network and of file writes, and whether this call put it in with `folders`. A refusal read
    /// back without this crate's profile in place may come from the folder or from another
    /// sandbox, which says nothing of the rest: unknown.
    pub(super) fn enter_sandbox(folders: &[String]) -> (Outcome, Outcome, bool) {
        // One call at a time: of two at once the second is refused, and must still find the
        // first one's success.
        static ENTERING: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _entering = ENTERING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut granted = false;
        if !ENTERED.load(Ordering::Relaxed)
            && let Some(profile) = profile(folders)
        {
            let mut error = ptr::null_mut();
            // SAFETY: the profile is a NUL-terminated text; on a failure the call allocates a
            // message into `error`, freed below.
            let entered = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) } == 0;
            if !error.is_null() {
                // SAFETY: frees the message sandbox_init allocated, once.
                unsafe { sandbox_free_error(error) };
            }
            // Never back to false: a profile that went in stays in.
            ENTERED.fetch_or(entered, Ordering::Relaxed);
            granted = entered && !folders.is_empty();
        }
        let outcome = |refused: bool| match (ENTERED.load(Ordering::Relaxed), refused) {
            (true, true) => Outcome::Confirmed,
            (false, true) => Outcome::Unknown,
            (_, false) => Outcome::Refused,
        };
        (
            outcome(network_refused()),
            outcome(file_writes_refused()),
            granted,
        )
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

/// The shared mappings the process can write, region by region from the kernel: shared modes
/// whose highest protection allows writing. `None` when the walk cannot be read whole, which it
/// checks by finding the regions of this function's code, its stack and the heap. Not on iOS.
pub(crate) fn shared_mappings() -> Option<Vec<crate::SharedMapping>> {
    #[cfg(target_os = "macos")]
    return macos::shared_mappings();
    #[cfg(not(target_os = "macos"))]
    None
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
        (P::FolderWrites, O::Confirmed) => {
            "this call put the sandbox in with a write rule beneath each folder"
        }
        (P::FolderWrites, O::Refused) => {
            "a folder was no longer the new, empty one made, its path could not go into the \
             profile, or the sandbox was in already or refused"
        }
        (P::WholeProcess, O::Confirmed) => "this platform applies isolation at process scope",
        _ => return None,
    })
}
