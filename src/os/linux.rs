//! Linux and Android: secret memory, the seccomp filter, Landlock, namespaces, and the probes that
//! check them.
//!
//! An Android app's own seccomp policy kills the process on calls it doesn't expect, so on Android
//! this module skips secret memory, Landlock, `unshare` and io_uring.
#![allow(
    unsafe_code,
    reason = "memfd_secret, ftruncate, mmap, madvise, getrandom, munmap, sysconf, prctl, unshare, \
              socket, open, close and the io_uring and Landlock calls are foreign functions, and \
              a new mapping is written through a raw pointer"
)]

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::ptr::NonNull;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

use crate::protect::{Isolation, Options};

/// The number of `memfd_secret` on x86-64 and AArch64, the Linux architectures this crate is
/// tested on, where it is called; on another one it is `None`, and a secret takes anonymous pages.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const MEMFD_SECRET: Option<libc::c_long> = Some(libc::SYS_memfd_secret);
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
const MEMFD_SECRET: Option<libc::c_long> = None;

/// `bytes` bytes of secret memory, or `None` where the kernel refuses: one without secret memory,
/// a policy that forbids the call, or a request beyond RLIMIT_MEMLOCK, which these pages count
/// against and which an older kernel refuses at mmap, a newer one at the first touch of a page.
#[cfg(target_os = "linux")]
pub(super) fn secret_pages(bytes: usize) -> Option<NonNull<u8>> {
    let number = MEMFD_SECRET?;
    // O_CLOEXEC from the start: a program that another thread starts before this function closes
    // the descriptor does not get it, and so cannot map the secret.
    // SAFETY: memfd_secret takes one flags argument and returns a new descriptor or -1.
    let descriptor = unsafe { libc::syscall(number, libc::O_CLOEXEC) };
    let descriptor = i32::try_from(descriptor).ok().filter(|&fd| fd >= 0)?;
    // SAFETY: the descriptor was just opened and nothing else owns it; it is closed on return,
    // while the mapping stays.
    let file = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let size = libc::off_t::try_from(bytes).ok()?;
    // SAFETY: ftruncate sizes the file of a descriptor this function owns.
    if unsafe { libc::ftruncate(file.as_raw_fd(), size) } != 0 {
        return None;
    }
    let start = super::unix::reserve(bytes)?;
    // SAFETY: a shared mapping of that file, between the guard pages of the reservation just
    // made, which nothing else refers to and which it replaces there.
    let mapped = unsafe {
        libc::mmap(
            start.as_ptr().cast(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_FIXED,
            file.as_raw_fd(),
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        super::unix::release(start, bytes);
        return None;
    }
    // The mapping is shared, so a child process would share the secret: it gets no mapping
    // instead, or the pages are given back and anonymous ones taken.
    // SAFETY: madvise marks the pages of the mapping just made and changes no content.
    if unsafe { libc::madvise(mapped, bytes, libc::MADV_DONTFORK) } != 0
        || !charge_pages(mapped, bytes)
    {
        super::unix::release(start, bytes);
        return None;
    }
    Some(start)
}

/// Touches every page of new secret memory, so the lock limit is charged now. Newer kernels charge
/// it at the first fault and send SIGBUS when over the limit, which would kill the process at its
/// first write. A byte written by `getrandom` from inside the kernel only gets EFAULT. It is the raw
/// syscall because the vDSO version would fault in user space.
#[cfg(target_os = "linux")]
fn charge_pages(mapped: *mut libc::c_void, bytes: usize) -> bool {
    // SAFETY: sysconf takes an integer and touches no memory of this process.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    for offset in (0..bytes).step_by(page) {
        let byte = mapped.cast::<u8>().wrapping_add(offset);
        // SAFETY: getrandom writes at most the one byte it is asked for, at `byte`, inside the
        // mapping, to which nothing else refers yet.
        if unsafe { libc::syscall(libc::SYS_getrandom, byte, 1usize, 0u32) } != 1 {
            return false;
        }
        // Secret memory starts zeroed.
        // SAFETY: the byte lies in the mapping, on the page the kernel just wrote to.
        unsafe { byte.write_volatile(0) };
    }
    true
}

/// The error number of a call that the filter or Landlock refuses. Both answer before the call
/// itself, so a refusal with another number did not come from them.
const REFUSED: i32 = libc::EACCES;

pub(crate) fn enter(options: Options) -> Isolation {
    let whole_process = one_thread();
    #[cfg(target_os = "linux")]
    let empty_network = whole_process && enter_own_namespaces() && network_empty();
    #[cfg(target_os = "android")]
    let empty_network = false;
    let core_limit = super::unix::forbid_core_dumps();
    // SAFETY: PR_SET_DUMPABLE takes integers and touches no memory of this process. Once the
    // filter holds, it refuses this call, and the flag stays 0.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let speculation_limited = limit_speculation();
    // Seccomp and Landlock require no_new_privs of an unprivileged process: no program it starts
    // can gain privileges, as a set-user-ID program would.
    let wanted = (u32::from(options.file_locks) * seccomp::FILE_LOCKS)
        | (u32::from(options.sendmsg) * seccomp::SENDMSG)
        | (u32::from(options.own_signals) * seccomp::SIGNALS);
    let memory_locked = options.lock_all && lock_all_memory();
    // SAFETY: as above.
    let held = if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0 {
        restrict(whole_process, wanted)
    } else {
        None
    };
    let filtered = held.is_some();
    // SAFETY: PR_GET_DUMPABLE takes no pointer and returns the flag.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0;
    Isolation {
        // A pipe in core_pattern, as systemd-coredump and apport use, ignores RLIMIT_CORE: there
        // only a process that is not dumpable keeps a crash off the disk.
        no_core_dumps: core_limit && !dumpable,
        // A tracer attached before the call keeps reading, whatever the flag says.
        no_memory_reading: !dumpable && !traced(),
        no_new_sockets: sockets_refused(),
        empty_network,
        // Only the filter refuses every change of a file, by the calls and the flags of an open;
        // Landlock alone leaves modes, owners, extended attributes and times.
        no_file_changes: filtered && writing_refused(),
        speculation_limited,
        whole_process,
        file_locks_refused: file_locks_refused(),
        sendmsg_refused: sendmsg_refused(),
        foreign_signals_refused: held.is_some_and(|options| options & seccomp::SIGNALS != 0)
            || signals_scoped(held.is_some()),
        memory_locked,
        ..Isolation::default()
    }
}

/// Keeps every page of the process, now and later, out of swap. Pages are locked as they are
/// first touched (`MCL_ONFAULT`), so a large reservation costs nothing until it is used.
fn lock_all_memory() -> bool {
    // SAFETY: mlockall takes flags and touches no memory of this process.
    unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | MCL_ONFAULT) == 0 }
}

/// `MCL_ONFAULT` of linux/mman.h, which libc gives only for some targets.
const MCL_ONFAULT: libc::c_int = 4;

/// Whether this thread's Landlock layer blocks signals to other processes, which takes Landlock's
/// ABI 6 (Linux 6.12). A thread holding the filter holds the layer too, since the layer goes first.
#[cfg(target_os = "linux")]
fn signals_scoped(filtered: bool) -> bool {
    let layered = filtered || LAYERED_THREAD.get() || LAYERED_PROCESS.load(Ordering::Relaxed);
    // SAFETY: with a null attribute and the version flag the call only returns a number.
    let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0_usize, 0_usize, 1_u32) };
    layered && abi >= 6
}

#[cfg(target_os = "android")]
fn signals_scoped(_filtered: bool) -> bool {
    false
}

/// Whether a file lock is refused: a lock on /dev/null, opened for reading, which nothing else
/// locks.
fn file_locks_refused() -> bool {
    // SAFETY: the path is a NUL-terminated literal; open touches nothing else.
    let file = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if file < 0 {
        return false;
    }
    // SAFETY: flock takes the descriptor just opened and touches no memory.
    let locked = unsafe { libc::flock(file, libc::LOCK_SH | libc::LOCK_NB) };
    let refused = locked != 0 && std::io::Error::last_os_error().raw_os_error() == Some(REFUSED);
    // SAFETY: closes the descriptor opened above, once; closing drops a lock it took.
    unsafe { libc::close(file) };
    refused
}

/// Whether `sendmsg` is refused, by its answer for a descriptor of -1, which is EBADF without the
/// filter.
fn sendmsg_refused() -> bool {
    // SAFETY: a descriptor of -1 and a null message: without the filter the call fails at once.
    let sent = unsafe { libc::syscall(libc::SYS_sendmsg, -1_i64, 0_i64, 0_i64) };
    sent < 0 && std::io::Error::last_os_error().raw_os_error() == Some(REFUSED)
}

#[cfg(target_os = "linux")]
thread_local! {
    /// Whether this thread holds the Landlock layer of an earlier call.
    static LAYERED_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the Landlock layer was applied while the process had one thread, so that every thread
/// holds it.
#[cfg(target_os = "linux")]
static LAYERED_PROCESS: AtomicBool = AtomicBool::new(false);

/// Gives this thread the Landlock layer and the seccomp filter, if it doesn't have them yet, and
/// returns the options of the filter it now holds (`None` if none).
///
/// Only what the kernel accepted is recorded, so a refusal is retried next time and nothing is
/// stacked twice. A filter installed by someone else (Android, containers) doesn't count.
fn restrict(whole_process: bool, wanted: u32) -> Option<u32> {
    let held = seccomp::held();
    if let Some(options) = held
        && options & wanted == wanted
    {
        return held;
    }
    #[cfg(target_os = "linux")]
    if !(LAYERED_THREAD.get() || LAYERED_PROCESS.load(Ordering::Relaxed))
        && landlock_layer::restrict_self()
    {
        LAYERED_THREAD.set(true);
        if whole_process {
            LAYERED_PROCESS.store(true, Ordering::Relaxed);
        }
    }
    #[cfg(target_os = "android")]
    let _ = whole_process;
    seccomp::install(held.unwrap_or(0) | wanted).or(held)
}

/// `prctl` options of linux/prctl.h for the processor's speculation, written out because libc
/// gives them other types on Linux and Android.
const GET_SPECULATION: libc::c_int = 52;
const SET_SPECULATION: libc::c_int = 53;
/// Speculative store bypass (Spectre variant 4) and indirect branch speculation (variant 2, from
/// other processes).
const SPECULATIONS: [libc::c_ulong; 2] = [0, 1];
/// The answers: not affected; disabled; disabled for good.
const SPEC_NOT_AFFECTED: libc::c_int = 0;
const SPEC_DISABLE: libc::c_int = 1 << 2;
const SPEC_FORCE_DISABLE: libc::c_int = 1 << 3;

/// Turns off speculative store bypass and indirect branch speculation for good (Spectre v4 and v2).
/// The kernel leaves both to each program because they cost speed. Returns whether both are off or
/// not needed on this processor.
fn limit_speculation() -> bool {
    SPECULATIONS.iter().all(|&which| {
        // SAFETY: prctl takes integers and touches no memory of this process.
        unsafe {
            libc::prctl(
                SET_SPECULATION,
                which,
                SPEC_FORCE_DISABLE as libc::c_ulong,
                0,
                0,
            );
        }
        // SAFETY: as above.
        let state = unsafe { libc::prctl(GET_SPECULATION, which, 0, 0, 0) };
        let unknown_here =
            state < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODEV);
        state == SPEC_NOT_AFFECTED
            || state > 0 && state & (SPEC_DISABLE | SPEC_FORCE_DISABLE) != 0
            || which == 1 && unknown_here
    })
}

/// Whether a tracer, such as a debugger the process was started under, is attached to the calling
/// thread, as its `TracerPid` line says; a status that cannot be read counts as traced.
fn traced() -> bool {
    std::fs::read_to_string("/proc/thread-self/status").map_or(true, |status| {
        status
            .lines()
            .find_map(|line| line.strip_prefix("TracerPid:"))
            .is_none_or(|tracer| tracer.trim() != "0")
    })
}

/// Whether the process has one thread: only then may it enter a user namespace of its own, and
/// only then do the filters, which a thread passes on to the threads it starts, hold for the whole
/// process. An Android app always has other threads.
fn one_thread() -> bool {
    #[cfg(target_os = "linux")]
    return std::fs::read_dir("/proc/self/task").is_ok_and(|threads| threads.count() == 1);
    #[cfg(target_os = "android")]
    false
}

/// Moves the process into its own empty network namespace and its own IPC namespace, inside a new
/// user namespace (needed without root). The kernel allows this only for a single-threaded process.
/// Returns whether the network namespace exists now, from this call or an earlier one.
#[cfg(target_os = "linux")]
fn enter_own_namespaces() -> bool {
    static MADE: AtomicBool = AtomicBool::new(false);
    // SAFETY: unshare takes flags only and touches no memory of this process.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } == 0 {
        MADE.store(true, Ordering::Relaxed);
        // The user namespace just made allows it; a refusal leaves the shared objects, which the
        // filter refuses anyway where it is written.
        // SAFETY: as above.
        unsafe { libc::unshare(libc::CLONE_NEWIPC) };
    }
    MADE.load(Ordering::Relaxed)
}

/// Whether the network namespace holds only the loopback interface and no IPv4 route. The kernel
/// lists the interfaces after two heading lines, each as "name: counters", and the routes after a
/// heading that starts with "Iface"; an empty table may lack that heading.
#[cfg(target_os = "linux")]
fn network_empty() -> bool {
    /// Heading lines of /proc/net/dev.
    const DEVICE_HEADINGS: usize = 2;
    let (Ok(devices), Ok(routes)) = (
        std::fs::read_to_string("/proc/self/net/dev"),
        std::fs::read_to_string("/proc/self/net/route"),
    ) else {
        return false;
    };
    let only_loopback = devices
        .lines()
        .skip(DEVICE_HEADINGS)
        .filter_map(|line| line.split(':').next())
        .all(|name| name.trim() == "lo");
    let no_route = routes
        .lines()
        .all(|line| line.trim().is_empty() || line.starts_with("Iface"));
    only_loopback && no_route
}

/// `Ok` after closing what a probe opened, else the error number of the refusal.
fn opened(descriptor: libc::c_long) -> Result<(), i32> {
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    // SAFETY: closes the descriptor the probe just opened, once.
    unsafe { libc::close(descriptor as libc::c_int) };
    Ok(())
}

/// Whether the filter refuses a new socket and, on Linux, an io_uring. The probe asks for a Unix
/// socket: Android refuses a network socket with EACCES as well to an app without the `INTERNET`
/// permission, which must not pass for the filter.
fn sockets_refused() -> bool {
    // SAFETY: socket takes integers and touches no memory of this process.
    let socket = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    let refused = opened(socket.into()) == Err(REFUSED);
    // An io_uring could open a socket without the socket call. An Android app's policy ends the
    // process at any io_uring call, so it is not probed there; the filter refuses it all the same.
    #[cfg(target_os = "linux")]
    return refused && io_uring_refused();
    #[cfg(target_os = "android")]
    refused
}

#[cfg(target_os = "linux")]
fn io_uring_refused() -> bool {
    // `struct io_uring_params` of linux/io_uring.h is 120 bytes; zero asks for the defaults.
    let mut params = [0u8; 120];
    // SAFETY: the kernel reads and fills the 120 bytes of `params`, which live for the call.
    let ring = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
    opened(ring) == Err(REFUSED)
}

/// Whether opening /dev/null for writing is refused by the filter or Landlock. A system without
/// /dev/null, or one that refuses it for another reason, cannot tell.
fn writing_refused() -> bool {
    // SAFETY: the path is a NUL-terminated literal; open touches nothing else.
    let file = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    opened(file.into()) == Err(REFUSED)
}

/// The seccomp filter, for x86-64 and little-endian AArch64. It refuses (EACCES) new sockets and
/// io_uring, file system changes, ioctls other than the terminal's, new peers for old sockets,
/// System V IPC, POSIX queues, the keyring, `execve`, calls on other processes, kernel interfaces a
/// secret command never needs, and the `prctl` options that undo the dump settings. Calls newer
/// than its table get ENOSYS, so libc falls back to ones the filter can check.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
))]
mod seccomp {
    /// The numbers of Linux 7.0's arch/x86/entry/syscalls/syscall_64.tbl, written out because
    /// libc 0.2.191 lacks some of them.
    #[cfg(target_arch = "x86_64")]
    mod calls {
        /// AUDIT_ARCH_X86_64 of linux/audit.h.
        pub(super) const ARCH: u32 = 0xC000_003E;
        /// An x32 call carries this bit in its number (__X32_SYSCALL_BIT).
        pub(super) const X32_BIT: u32 = 0x4000_0000;
        /// rseq_slice_yield, the newest call of Linux 7.0.
        pub(super) const NEWEST: u32 = 471;
        pub(super) const OPENAT2: u32 = 437;
        pub(super) const IOCTL: u32 = 16;
        pub(super) const PRCTL: u32 = 157;
        pub(super) const SENDTO: u32 = 44;
        /// Refused with the options of the same names.
        pub(super) const FLOCK: u32 = 73;
        pub(super) const FCNTL: u32 = 72;
        pub(super) const SENDMSG: u32 = 46;
        /// kill and rt_sigqueueinfo, whose first argument is a process; tgkill and
        /// rt_tgsigqueueinfo, whose first is a thread group; tkill and pidfd_send_signal.
        pub(super) const SIGNAL_TO_PROCESS: [u32; 4] = [62, 129, 234, 297];
        pub(super) const SIGNAL_OTHER: [u32; 2] = [200, 424];
        /// open, whose flags are its second argument, and openat, whose flags are its third.
        pub(super) const OPENS: &[(u32, u32)] = &[(2, 1), (257, 2)];
        /// Refused whatever their arguments. Not ftruncate: it sizes the secret memory of every
        /// `Secret`, and it changes only a file already open for writing, which `write` changes
        /// anyway.
        pub(super) const REFUSED: &[u32] = &[
            41, 53, // socket, socketpair
            425, 426, 427, // io_uring_setup, io_uring_enter, io_uring_register
            101, 311, 438, // ptrace, process_vm_writev, pidfd_getfd
            85, 304, // creat, open_by_handle_at
            82, 264, 316, // rename, renameat, renameat2
            87, 263, 84, // unlink, unlinkat, rmdir
            83, 258, 133, 259, // mkdir, mkdirat, mknod, mknodat
            86, 265, 88, 266, // link, linkat, symlink, symlinkat
            76, 285, // truncate, fallocate
            90, 91, 268, 452, // chmod, fchmod, fchmodat, fchmodat2
            92, 93, 94, 260, // chown, fchown, lchown, fchownat
            188, 189, 190, 463, // setxattr, lsetxattr, fsetxattr, setxattrat
            197, 198, 199, 466, // removexattr, lremovexattr, fremovexattr, removexattrat
            469, // file_setattr
            132, 235, 261, 280, // utime, utimes, futimesat, utimensat
            165, // mount
            428, 429, 430, 431, 432, 433, 442, 467, // the new mount calls, from open_tree
            42, 49, 50, 43, 288, 307, // connect, bind, listen, accept, accept4, sendmmsg
            68, 69, 70, 71, // msgget, msgsnd, msgrcv, msgctl
            29, 30, 31, 67, // shmget, shmat, shmctl, shmdt
            64, 65, 220, 66, // semget, semop, semtimedop, semctl
            240, 241, 242, 243, 244, 245, // mq_open to mq_getsetattr
            248, 249, 250, // add_key, request_key, keyctl
            310, // process_vm_readv
            59, 322, // execve, execveat
            323, 321, 298, // userfaultfd, bpf, perf_event_open
        ];
    }

    /// The numbers of Linux 7.0's scripts/syscall.tbl as AArch64 has them, written out because
    /// libc 0.2.191 lacks some of them. AArch64 has no open, creat, rename, unlink, rmdir, mkdir,
    /// mknod, link, symlink, chmod, chown, lchown, utime, utimes or futimesat.
    #[cfg(target_arch = "aarch64")]
    mod calls {
        /// AUDIT_ARCH_AARCH64 of linux/audit.h.
        pub(super) const ARCH: u32 = 0xC000_00B7;
        /// rseq_slice_yield, the newest call of Linux 7.0.
        pub(super) const NEWEST: u32 = 471;
        pub(super) const OPENAT2: u32 = 437;
        pub(super) const IOCTL: u32 = 29;
        pub(super) const PRCTL: u32 = 167;
        pub(super) const SENDTO: u32 = 206;
        /// Refused with the options of the same names.
        pub(super) const FLOCK: u32 = 32;
        pub(super) const FCNTL: u32 = 25;
        pub(super) const SENDMSG: u32 = 211;
        /// kill and rt_sigqueueinfo, whose first argument is a process; tgkill and
        /// rt_tgsigqueueinfo, whose first is a thread group; tkill and pidfd_send_signal.
        pub(super) const SIGNAL_TO_PROCESS: [u32; 4] = [129, 138, 131, 240];
        pub(super) const SIGNAL_OTHER: [u32; 2] = [130, 424];
        /// openat, whose flags are its third argument.
        pub(super) const OPENS: &[(u32, u32)] = &[(56, 2)];
        /// Refused whatever their arguments. Not ftruncate: it sizes the secret memory of every
        /// `Secret`, and it changes only a file already open for writing, which `write` changes
        /// anyway.
        pub(super) const REFUSED: &[u32] = &[
            198, 199, // socket, socketpair
            425, 426, 427, // io_uring_setup, io_uring_enter, io_uring_register
            117, 271, 438, // ptrace, process_vm_writev, pidfd_getfd
            265, // open_by_handle_at
            38, 276, // renameat, renameat2
            35,  // unlinkat
            34, 33, // mkdirat, mknodat
            37, 36, // linkat, symlinkat
            45, 47, // truncate, fallocate
            52, 53, 452, // fchmod, fchmodat, fchmodat2
            55, 54, // fchown, fchownat
            5, 6, 7, 463, // setxattr, lsetxattr, fsetxattr, setxattrat
            14, 15, 16, 466, // removexattr, lremovexattr, fremovexattr, removexattrat
            469, // file_setattr
            88,  // utimensat
            40,  // mount
            428, 429, 430, 431, 432, 433, 442, 467, // the new mount calls, from open_tree
            203, 200, 201, 202, 242, 269, // connect, bind, listen, accept, accept4, sendmmsg
            186, 189, 188, 187, // msgget, msgsnd, msgrcv, msgctl
            194, 196, 195, 197, // shmget, shmat, shmctl, shmdt
            190, 193, 192, 191, // semget, semop, semtimedop, semctl
            180, 181, 182, 183, 184, 185, // mq_open to mq_getsetattr
            217, 218, 219, // add_key, request_key, keyctl
            270, // process_vm_readv
            221, 281, // execve, execveat
            282, 280, 241, // userfaultfd, bpf, perf_event_open
        ];
    }

    /// The terminal's requests, which a program that reads a hidden line makes: TCGETS, TCSETS,
    /// TCSETSW and TCSETSF, their termios2 forms, which newer C libraries use (glibc 2.42 and
    /// later), and TIOCGWINSZ. Tracing a terminal program that reads hidden input with glibc 2.43
    /// shows no other.
    const TERMINAL_REQUESTS: [u32; 9] = [
        libc::TCGETS as u32,
        libc::TCSETS as u32,
        libc::TCSETSW as u32,
        libc::TCSETSF as u32,
        libc::TCGETS2 as u32,
        libc::TCSETS2 as u32,
        libc::TCSETSW2 as u32,
        libc::TCSETSF2 as u32,
        libc::TIOCGWINSZ as u32,
    ];

    /// The flags of an open that can change a file.
    const WRITE_FLAGS: u32 =
        (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u32;

    /// A `prctl` option that no kernel has: without this crate's filter the kernel answers EINVAL,
    /// and another filter answers as it does; this crate's filter answers [`MARK`] with its
    /// options. The four bytes read "SPC1".
    const MARK_OPTION: u32 = 0x5350_4331;
    /// The error numbers of that answer, beyond every one a kernel gives (MAX_ERRNO is 4095): this
    /// base with the bits of the filter's options in its low four bits, the sign that a thread
    /// holds this crate's filter, whoever installed it. A filter that refuses other calls gets
    /// another base.
    const MARK: u32 = 0xF00;
    /// The options of a filter, as bits of the mark.
    pub(super) const FILE_LOCKS: u32 = 1;
    pub(super) const SENDMSG: u32 = 2;
    pub(super) const SIGNALS: u32 = 4;
    /// The lock commands of `fcntl`: F_SETLK, F_SETLKW, F_OFD_SETLK and F_OFD_SETLKW.
    const LOCK_COMMANDS: [u32; 4] = [6, 7, 37, 38];

    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const REFUSE: u32 = libc::SECCOMP_RET_ERRNO | super::REFUSED as u32;
    const NO_SUCH_CALL: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;

    /// Offsets in `struct seccomp_data` (linux/seccomp.h): `int nr`, `__u32 arch`, then from 16
    /// the six `__u64` arguments.
    const NUMBER_OFFSET: u32 = 0;
    const ARCH_OFFSET: u32 = 4;

    /// The offset of the low half of an argument, on a little-endian system: all that the kernel
    /// reads of an `int` or `unsigned int` argument, such as the flags of an open or the request
    /// of an ioctl.
    const fn argument(index: u32) -> u32 {
        16 + 8 * index
    }

    /// Instruction codes of linux/bpf_common.h, which libc does not give for Android.
    const LOAD_WORD: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const IF_EQUAL: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const IF_ABOVE: u16 = 0x25; // BPF_JMP | BPF_JGT | BPF_K
    #[cfg(target_arch = "x86_64")]
    const IF_AT_LEAST: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
    const IF_ANY_BIT: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
    const RETURN: u16 = 0x06; // BPF_RET | BPF_K

    fn instruction(code: u16, if_true: u8, if_false: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: if_true,
            jf: if_false,
            k,
        }
    }

    /// Runs `body`, which ends in answers, for the call `number`, and skips it for any other.
    fn for_call(number: u32, body: &[libc::sock_filter]) -> Vec<libc::sock_filter> {
        let mut block = vec![instruction(IF_EQUAL, 0, body.len() as u8, number)];
        block.extend_from_slice(body);
        block
    }

    /// Returns `action` when the loaded value passes `test` with `value`, else goes on.
    fn answer_if(test: u16, value: u32, action: u32) -> [libc::sock_filter; 2] {
        [
            instruction(test, 0, 1, value),
            instruction(RETURN, 0, 0, action),
        ]
    }

    /// The filter, in which every test is followed by the answer it leads to, or skips a block
    /// that ends in answers, so that no jump goes further than the block it belongs to.
    fn program(options: u32) -> Vec<libc::sock_filter> {
        let mut program = vec![instruction(LOAD_WORD, 0, 0, ARCH_OFFSET)];
        // A call of another ABI, such as a 32-bit one, has other numbers: it is refused.
        program.extend([
            instruction(IF_EQUAL, 1, 0, calls::ARCH),
            instruction(RETURN, 0, 0, REFUSE),
            instruction(LOAD_WORD, 0, 0, NUMBER_OFFSET),
        ]);
        #[cfg(target_arch = "x86_64")]
        program.extend(answer_if(IF_AT_LEAST, calls::X32_BIT, REFUSE));
        program.extend(answer_if(IF_ABOVE, calls::NEWEST, NO_SUCH_CALL));
        program.extend(answer_if(IF_EQUAL, calls::OPENAT2, NO_SUCH_CALL));
        for &number in calls::REFUSED {
            program.extend(answer_if(IF_EQUAL, number, REFUSE));
        }
        if options & FILE_LOCKS != 0 {
            program.extend(answer_if(IF_EQUAL, calls::FLOCK, REFUSE));
            let mut commands = vec![instruction(LOAD_WORD, 0, 0, argument(1))];
            for command in LOCK_COMMANDS {
                commands.extend(answer_if(IF_EQUAL, command, REFUSE));
            }
            commands.push(instruction(RETURN, 0, 0, ALLOW));
            program.extend(for_call(calls::FCNTL, &commands));
        }
        if options & SENDMSG != 0 {
            program.extend(answer_if(IF_EQUAL, calls::SENDMSG, REFUSE));
        }
        if options & SIGNALS != 0 {
            // The process's own number, as `kill` and `tgkill` take it.
            // SAFETY: getpid takes nothing and touches no memory.
            let own = unsafe { libc::getpid() } as u32;
            for number in calls::SIGNAL_TO_PROCESS {
                program.extend(for_call(
                    number,
                    &[
                        instruction(LOAD_WORD, 0, 0, argument(0)),
                        instruction(IF_EQUAL, 0, 1, own),
                        instruction(RETURN, 0, 0, ALLOW),
                        instruction(RETURN, 0, 0, REFUSE),
                    ],
                ));
            }
            for number in calls::SIGNAL_OTHER {
                program.extend(answer_if(IF_EQUAL, number, REFUSE));
            }
        }
        // The mark, which a probe reads, and the two options that would let other programs of
        // the user read the memory again; every other prctl is allowed.
        let marked = libc::SECCOMP_RET_ERRNO | MARK | options;
        let mut prctl = vec![instruction(LOAD_WORD, 0, 0, argument(0))];
        prctl.extend(answer_if(IF_EQUAL, MARK_OPTION, marked));
        prctl.extend(answer_if(IF_EQUAL, libc::PR_SET_DUMPABLE as u32, REFUSE));
        prctl.extend(answer_if(IF_EQUAL, libc::PR_SET_PTRACER as u32, REFUSE));
        prctl.push(instruction(RETURN, 0, 0, ALLOW));
        program.extend(for_call(calls::PRCTL, &prctl));
        // A datagram with an address of its own, through a socket opened before: only a call
        // without one, on a socket connected before, is allowed. The address is a 64-bit pointer.
        program.extend(for_call(
            calls::SENDTO,
            &[
                instruction(LOAD_WORD, 0, 0, argument(4)),
                instruction(IF_EQUAL, 1, 0, 0),
                instruction(RETURN, 0, 0, REFUSE),
                instruction(LOAD_WORD, 0, 0, argument(4) + 4),
                instruction(IF_EQUAL, 1, 0, 0),
                instruction(RETURN, 0, 0, REFUSE),
                instruction(RETURN, 0, 0, ALLOW),
            ],
        ));
        for &(number, flags) in calls::OPENS {
            program.extend([
                instruction(IF_EQUAL, 0, 4, number),
                instruction(LOAD_WORD, 0, 0, argument(flags)),
                instruction(IF_ANY_BIT, 0, 1, WRITE_FLAGS),
                instruction(RETURN, 0, 0, REFUSE),
                instruction(RETURN, 0, 0, ALLOW),
            ]);
        }
        // Last, as its final answer allows every other call: an ioctl is allowed only with a
        // terminal request, each test of which jumps to that answer.
        let requests = TERMINAL_REQUESTS.len() as u8;
        program.extend([
            instruction(IF_EQUAL, 0, requests + 2, calls::IOCTL),
            instruction(LOAD_WORD, 0, 0, argument(1)),
        ]);
        for (index, &request) in (0..).zip(&TERMINAL_REQUESTS) {
            program.push(instruction(IF_EQUAL, requests - index, 0, request));
        }
        program.extend([
            instruction(RETURN, 0, 0, REFUSE),
            instruction(RETURN, 0, 0, ALLOW),
        ]);
        program
    }

    /// The options of this crate's filter that the calling thread holds, from its own call or from
    /// the thread that started it, or `None` for none: only this filter answers [`MARK_OPTION`]
    /// with [`MARK`]. Of two such filters, the newer answers.
    pub(super) fn held() -> Option<u32> {
        // SAFETY: prctl takes integers; with an option that no kernel has it changes nothing and
        // touches no memory of this process.
        let result = unsafe { libc::prctl(MARK_OPTION as libc::c_int, 0, 0, 0, 0) };
        let error = std::io::Error::last_os_error().raw_os_error()?;
        let error = u32::try_from(error).ok()?;
        (result == -1 && error & !0xF == MARK).then_some(error & 0xF)
    }

    /// Installs the filter with `options` for the calling thread and the threads it starts
    /// afterwards, and returns the options of the filter it holds now.
    pub(super) fn install(options: u32) -> Option<u32> {
        let mut program = program(options);
        let filter = libc::sock_fprog {
            len: program.len() as u16,
            filter: program.as_mut_ptr(),
        };
        // SAFETY: the filter points to `len` instructions that live for the call; the kernel
        // copies them. It holds for the calling thread and the threads it starts afterwards.
        let installed = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &raw const filter,
                0,
                0,
            )
        } == 0;
        if installed { held() } else { None }
    }
}

/// No filter is written for other architectures: there Landlock alone restricts Linux.
#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
)))]
mod seccomp {
    pub(super) const FILE_LOCKS: u32 = 1;
    pub(super) const SENDMSG: u32 = 2;
    pub(super) const SIGNALS: u32 = 4;

    pub(super) fn held() -> Option<u32> {
        None
    }

    pub(super) fn install(_options: u32) -> Option<u32> {
        None
    }
}

/// The Landlock layer: no file may be changed anywhere, and on newer kernels no TCP bind or connect,
/// no connection to UNIX sockets outside the layer and no signals to other processes. Reading stays
/// allowed. Rights the running kernel doesn't know are skipped.
#[cfg(target_os = "linux")]
mod landlock_layer {
    use landlock::{ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetStatus, Scope};

    /// The newest Landlock ABI whose rights the layer asks for: that of Linux 7.1.
    const ASKED: ABI = ABI::V9;

    /// Applies the layer to the calling thread and the threads it starts afterwards, and returns
    /// whether the kernel took it, whole or with the rights it knows. A kernel without Landlock,
    /// or one that refuses the layer, leaves the thread as it was.
    pub(super) fn restrict_self() -> bool {
        Ruleset::default()
            .handle_access(AccessFs::from_write(ASKED))
            .and_then(|ruleset| ruleset.handle_access(AccessNet::from_all(ASKED)))
            .and_then(|ruleset| ruleset.scope(Scope::AbstractUnixSocket | Scope::Signal))
            .and_then(Ruleset::create)
            .and_then(|created| created.restrict_self())
            .is_ok_and(|status| status.ruleset != RulesetStatus::NotEnforced)
    }
}

/// Whether a protection always holds for the whole process here, and what confirms it.
pub(crate) fn measure(protection: crate::Protection) -> (bool, &'static str) {
    use crate::Protection::*;
    match protection {
        NoCoreDumps => (
            true,
            "RLIMIT_CORE reads back 0 and the process is not dumpable",
        ),
        NoMemoryReading => (true, "not dumpable, and no tracer in TracerPid"),
        NoNewSockets => (false, "a new socket is refused"),
        EmptyNetwork => (true, "only a loopback interface, down, and no route"),
        NoFileChanges => (
            false,
            "the filter answers its mark, and opening for writing is refused",
        ),
        SpeculationLimited => (false, "PR_GET_SPECULATION_CTRL reads back disabled"),
        WholeProcess => (true, "the process had one thread when the filter went in"),
        FileLocksRefused => (false, "a lock on /dev/null is refused"),
        SendmsgRefused => (false, "sendmsg is refused"),
        ForeignSignalsRefused => (
            false,
            "the filter answers its mark, or Landlock is 6.12 or later",
        ),
        MemoryLocked => (true, "mlockall accepted"),
        DynamicCodeRefused | MicrosoftSignedOnly => (true, "Windows only"),
    }
}
