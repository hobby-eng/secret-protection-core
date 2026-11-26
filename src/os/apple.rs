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
        // Before the sandbox, which may not allow the calls. PT_DENY_ATTACH stops ptrace, not
        // task_for_pid: only the signature's hardened runtime, without get-task-allow, keeps a
        // debugging tool of the user from the memory.
        let reading = match (macos::refuse_debuggers(), macos::hardened()) {
            (Outcome::Confirmed, Some(true)) => Outcome::Confirmed,
            (Outcome::Confirmed, _) => Outcome::Unknown,
            (refused, _) => refused,
        };
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
        fn csops(
            pid: libc::pid_t,
            ops: libc::c_uint,
            status: *mut libc::c_void,
            size: libc::size_t,
        ) -> libc::c_int;
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
    /// not mode or owner changes. The ioctls are not named, so the profile does not rely on
    /// refusing TIOCSTI, input the shell reads as the user's, through a controlling terminal: a
    /// worker has none (`setsid`).
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

    /// The terminals among the standard streams, by path; only plain device names, letters and
    /// digits with dots, dashes and underscores after the first (`/dev/cu.usbserial-10`), which
    /// the profile's text can hold as they are.
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
                rest.bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphanumeric())
                    && (rest.bytes()).all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            });
            if plain && !found.contains(&path) {
                found.push(path);
            }
        }
        found
    }
    /// CS_OPS_STATUS of sys/codesign.h, and the status flags it reports: the hardened runtime, and
    /// the get-task-allow entitlement, which lets a debugger in anyway.
    const STATUS: libc::c_uint = 0;
    const RUNTIME: u32 = 0x0001_0000;
    const GET_TASK_ALLOW: u32 = 0x0000_0004;

    /// Whether the code signature keeps other processes of the user from the memory: the hardened
    /// runtime, without get-task-allow. `None` when the status cannot be read.
    pub(super) fn hardened() -> Option<bool> {
        let mut flags = 0u32;
        // SAFETY: csops writes at most the four bytes of status into `flags`, which lives for
        // the call; getpid takes nothing.
        let read = unsafe {
            csops(
                libc::getpid(),
                STATUS,
                (&raw mut flags).cast(),
                size_of::<u32>(),
            )
        } == 0;
        read.then_some(flags & RUNTIME != 0 && flags & GET_TASK_ALLOW == 0)
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

    /// The folders the profile in place grants, once this crate put it in.
    static GRANTED: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

    /// Whether this crate's profile is in place.
    pub(super) fn entered() -> bool {
        ENTERED.load(Ordering::Relaxed)
    }

    /// Whether the access list of the folder held by `descriptor` allows anything to anyone, or
    /// cannot be read.
    pub(crate) fn listed_access(descriptor: std::os::fd::RawFd) -> bool {
        use std::ffi::c_void;
        unsafe extern "C" {
            fn acl_get_fd(descriptor: libc::c_int) -> *mut c_void;
            fn acl_get_entry(
                list: *mut c_void,
                which: libc::c_int,
                entry: *mut *mut c_void,
            ) -> libc::c_int;
            fn acl_get_tag_type(entry: *mut c_void, tag: *mut libc::c_int) -> libc::c_int;
            fn acl_free(object: *mut c_void) -> libc::c_int;
        }
        /// ACL_FIRST_ENTRY, ACL_NEXT_ENTRY and ACL_EXTENDED_DENY of sys/acl.h: an entry of any
        /// other kind counts as allowing.
        const FIRST: libc::c_int = 0;
        const NEXT: libc::c_int = -1;
        const DENY: libc::c_int = 2;
        let errno = || io::Error::last_os_error().raw_os_error();
        // SAFETY: the calling thread's errno, which this thread alone writes.
        let clear = || unsafe { *libc::__error() = 0 };
        clear();
        // SAFETY: reads the list of an open descriptor; a list returned is freed below.
        let list = unsafe { acl_get_fd(descriptor) };
        if list.is_null() {
            // ENOENT: no list at all.
            return errno() != Some(libc::ENOENT);
        }
        let mut which = FIRST;
        let allows = loop {
            let mut entry = ptr::null_mut();
            clear();
            // SAFETY: the list read above; the call points `entry` at one of its entries.
            if unsafe { acl_get_entry(list, which, &mut entry) } != 0 {
                // EINVAL past the last entry.
                break errno() != Some(libc::EINVAL);
            }
            let mut tag = 0;
            // SAFETY: an entry of the list, which lives until the list is freed.
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || tag != DENY {
                break true;
            }
            which = NEXT;
        };
        // SAFETY: frees the list read above, once.
        unsafe { acl_free(list) };
        allows
    }

    /// Whether the volume of `descriptor` is mounted to ignore owners and modes, as macOS mounts
    /// many removable volumes, or cannot be told.
    pub(crate) fn owners_ignored(descriptor: std::os::fd::RawFd) -> bool {
        let mut volume = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: fstatfs fills the statfs when it succeeds.
        if unsafe { libc::fstatfs(descriptor, volume.as_mut_ptr()) } != 0 {
            return true;
        }
        // SAFETY: filled by the call that just succeeded.
        let volume = unsafe { volume.assume_init() };
        volume.f_flags & libc::MNT_IGNORE_OWNERSHIP.cast_unsigned() != 0
    }

    /// PROC_PIDREGIONPATHINFO and struct proc_regionwithpathinfo of sys/proc_info.h, which libc
    /// lacks: a region, and the file it maps, left zero when it maps none.
    const PROC_PIDREGIONPATHINFO: libc::c_int = 8;
    #[repr(C)]
    struct RegionWithPath {
        region: RegionInfo,
        file: libc::vnode_info_path,
    }
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
    /// PROC_REGION_SUBMAP and PROC_REGION_SHARED of sys/proc_info.h.
    const PROC_REGION_SUBMAP: u32 = 1;
    const PROC_REGION_SHARED: u32 = 2;
    /// The share modes of mach/vm_region.h that tell more than "shared".
    const SM_COW: u32 = 1;
    const SM_PRIVATE: u32 = 2;
    const SM_EMPTY: u32 = 3;
    const SM_TRUESHARED: u32 = 5;
    const SM_PRIVATE_ALIASED: u32 = 6;
    const SM_LARGE_PAGE: u32 = 8;
    /// VM_MEMORY_GENEALOGY of mach/vm_statistics.h: the tag of the buffer `os_log` shares with
    /// the log daemon, which the sandbox brings in as isolation starts.
    const LOG_BUFFER_TAG: u32 = 78;

    pub(super) fn shared_mappings() -> Option<Vec<crate::SharedMapping>> {
        let regions = regions()?;
        // How many of this process's own regions map each object, by its number and references:
        // a submap's belong to the system's shared map, and an empty one reads a count of 0.
        let mut ours = std::collections::BTreeMap::<(u32, u32), usize>::new();
        for (region, _, _) in &regions {
            if region.flags & PROC_REGION_SUBMAP == 0 && region.share_mode != SM_EMPTY {
                *ours.entry((region.obj_id, region.ref_count)).or_default() += 1;
            }
        }
        // The logging buffer is left out when it is the one region that looks like it: isolation
        // itself brings it in, and writes there reach the system log, as `os_log` calls do.
        let log_buffers = (regions.iter())
            .filter(|(region, _, maps_file)| log_buffer(region, *maps_file))
            .count();
        let mut found = Vec::new();
        for (region, path, maps_file) in regions {
            let elsewhere = usize::try_from(region.ref_count).ok()?
                > ours
                    .get(&(region.obj_id, region.ref_count))
                    .copied()
                    .unwrap_or(0);
            let reaches_others = match region.share_mode {
                // Taken to reach no one: an object above another (copy-on-write), nothing mapped
                // yet, superpages, and an object the system found only in this process.
                SM_COW | SM_EMPTY | SM_LARGE_PAGE | SM_PRIVATE_ALIASED => false,
                // An object of a pager, as a file's, mapped once with one more reference reads
                // as private and keeps a count of 2; so does a file mapped once, which reads 1
                // while written out, and a copy that holds all its pages, as dyld maps a
                // program's data: only a copy has pages found above another object, or swapped
                // out of itself.
                SM_PRIVATE => {
                    region.ref_count > 1
                        || (maps_file
                            && region.pages_shared_now_private == 0
                            && region.pages_swapped_out == 0)
                }
                // Not compared with this process's other regions by the system: an allocator's
                // guard pages, one object mapped twice, have no references beyond them.
                SM_TRUESHARED => elsewhere,
                // SM_SHARED and SM_SHARED_ALIASED: references beyond this process.
                _ => true,
            };
            // Memory a child of fork would share counts whatever its mode. A submap, as the
            // system's shared library cache is mapped, is no mapping of the program's.
            let shared = region.inheritance == libc::VM_INHERIT_SHARE as u32 || reaches_others;
            let shared = shared && region.flags & PROC_REGION_SUBMAP == 0;
            let left_out = log_buffers == 1 && log_buffer(&region, maps_file);
            if shared && !left_out && region.max_protection & libc::VM_PROT_WRITE as u32 != 0 {
                found.push(crate::SharedMapping {
                    start: usize::try_from(region.address).ok()?,
                    length: usize::try_from(region.size).ok()?,
                    name: String::from_utf8_lossy(&path).into_owned(),
                });
            }
        }
        Some(found)
    }

    /// Whether `region` looks like the buffer `os_log` shares with the log daemon: its tag, no
    /// file, kept from children, and shared. A region made to look the same cannot be told apart.
    fn log_buffer(region: &RegionInfo, maps_file: bool) -> bool {
        region.user_tag == LOG_BUFFER_TAG
            && !maps_file
            && region.inheritance == libc::VM_INHERIT_NONE as u32
            && region.flags & PROC_REGION_SHARED != 0
    }

    /// Every region of this process, the path of the file it maps, empty for none, and whether
    /// it maps one; `None` when the walk was cut short or missed the code, stack or heap of this
    /// process.
    fn regions() -> Option<Vec<(RegionInfo, Vec<u8>, bool)>> {
        let size = libc::c_int::try_from(std::mem::size_of::<RegionWithPath>()).ok()?;
        // SAFETY: getpid takes nothing and only answers.
        let pid = unsafe { libc::getpid() };
        let heap = std::hint::black_box(Box::new(0u8));
        let landmarks = [
            regions as *const () as usize as u64,
            &raw const size as usize as u64,
            &raw const *heap as usize as u64,
        ];
        let mut seen = [false; 3];
        let mut found = Vec::new();
        let mut address = 0u64;
        loop {
            let mut info = std::mem::MaybeUninit::<RegionWithPath>::zeroed();
            // SAFETY: the call writes at most `size` bytes, the size of the struct given.
            let got = unsafe {
                libc::proc_pidinfo(
                    pid,
                    PROC_PIDREGIONPATHINFO,
                    address,
                    info.as_mut_ptr().cast(),
                    size,
                )
            };
            if got == 0 {
                // EINVAL: no region at or after the address, the end; any other error leaves
                // the walk unread.
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                    break;
                }
                return None;
            }
            if got != size {
                return None;
            }
            // SAFETY: zeroed, then filled whole by the call that returned its size.
            let RegionWithPath { region, file } = unsafe { info.assume_init() };
            let end = region.address.checked_add(region.size)?;
            for (landmark, seen) in landmarks.iter().zip(&mut seen) {
                *seen |= (region.address..end).contains(landmark);
            }
            let path: Vec<u8> = (file.vip_path.as_flattened().iter())
                .map(|&unit| u8::from_ne_bytes(unit.to_ne_bytes()))
                .take_while(|&byte| byte != 0)
                .collect();
            let maps_file = file.vip_vi.vi_type != 0 || !path.is_empty();
            if end <= address {
                return None;
            }
            address = end;
            found.push((region, path, maps_file));
        }
        drop(heap);
        seen.iter().all(|&seen| seen).then_some(found)
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
            // Never back to false: a profile that went in stays in, with its folders.
            ENTERED.fetch_or(entered, Ordering::Relaxed);
            if entered {
                let _ = GRANTED.set(folders.to_vec());
            }
            granted = entered && !folders.is_empty();
        }
        let outcome = |refused: bool| match (ENTERED.load(Ordering::Relaxed), refused) {
            (true, true) => Outcome::Confirmed,
            (false, true) => Outcome::Unknown,
            (_, false) => Outcome::Refused,
        };
        // The probe keeps out of the folders the profile in place grants, whichever call put it.
        let grants = GRANTED.get().map_or(folders, Vec::as_slice);
        let files = file_writes_refused(grants).map_or(Outcome::Unknown, outcome);
        (outcome(network_refused()), files, granted)
    }

    /// Probes exclusive creation in the temporary directory, then /private/tmp, each where it
    /// exists outside the granted folders; a refusal that is not the sandbox's tries the next, and
    /// `None` is none left. An existing file is never opened or truncated. After successful
    /// creation, cleanup attempts to unlink the probe path.
    fn file_writes_refused(folders: &[String]) -> Option<bool> {
        // As the sandbox may compare names: without regard to letter case.
        let granted = |place: &std::path::Path| {
            let place = std::fs::canonicalize(place)
                .unwrap_or_else(|_| place.to_owned())
                .to_string_lossy()
                .to_lowercase();
            (folders.iter())
                .any(|folder| std::path::Path::new(&place).starts_with(folder.to_lowercase()))
        };
        // Only folders that exist: a TMPDIR that leads nowhere answers NotFound, which says
        // nothing of the sandbox.
        let places = [std::env::temp_dir(), "/private/tmp".into()]
            .into_iter()
            .filter(|place| place.is_dir() && !granted(place));
        for place in places {
            // A name no other user can take first, as /private/tmp is everyone's.
            let mut random = [0u8; 8];
            // SAFETY: getentropy fills the 8 bytes given, well within its 256.
            if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } != 0 {
                return None;
            }
            let path = place.join(format!(
                "secret-protection-core-{}-{:016x}",
                std::process::id(),
                u64::from_ne_bytes(random)
            ));
            let made = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path);
            match made {
                Ok(_) => {
                    let _ = std::fs::remove_file(&path);
                    return Some(false);
                }
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Some(true),
                // A name taken first, or a refusal that is not the sandbox's: the next place.
                Err(_) => {}
            }
        }
        None
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

#[cfg(target_os = "macos")]
pub(crate) use macos::{listed_access, owners_ignored};

/// The shared mappings the process can write, region by region from the kernel: memory whose
/// writes reach a file or another holder, or which a child of fork would share, whose highest
/// protection allows writing. `None` when the walk cannot be read whole: an error other than its
/// end, or no region of the walk's own code, its stack or the heap. Not on iOS.
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
        (P::NoMemoryReading, O::Confirmed) => {
            "PT_DENY_ATTACH accepted with no debugger attached, under the hardened runtime without \
             get-task-allow"
        }
        (P::NoMemoryReading, O::Refused) => "a debugger is attached, or PT_DENY_ATTACH was refused",
        (P::NoMemoryReading, O::Unknown) => {
            "the process could not be asked whether it is traced, or it runs without the hardened \
             runtime or with get-task-allow, so a debugging tool of the user may read it"
        }
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
            "a new file was refused, but this crate's sandbox profile is not in; or no place \
             to try one lies outside the granted folders, or its name was taken"
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
