//! Linux and Android.
//!
//! Linux's secret memory (`memfd_secret`, on by default since Linux 6.5): its pages leave the
//! kernel's direct map, so that no process, root included, reads them directly through
//! `/proc/PID/mem`, `process_vm_readv` or `PTRACE_PEEKDATA`; they stay out of swap and core dumps
//! by construction, and the kernel refuses to hibernate while they exist, so that they never reach
//! a hibernation image.
//! Android never calls it.
//!
//! The protections of [`crate::protect::Isolation::enter`]: the dump settings, a seccomp filter,
//! on Linux Landlock and an empty network namespace, and the probes that read them back. An
//! Android app's own seccomp policy ends the process at a call outside it, so there only `prctl`,
//! `prlimit64`, `socket`, `openat`, `close` and the memory calls are made: no Landlock, `unshare`,
//! io_uring or listing of the process's threads.
#![allow(
    unsafe_code,
    reason = "memfd_secret, ftruncate, mmap, madvise, getrandom, munmap, sysconf, prctl, unshare, \
              socket, open, close and the io_uring and Landlock calls are foreign functions, and \
              a new mapping is written through a raw pointer"
)]

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::protect::Isolation;

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
    // SAFETY: a new shared mapping of that file, at an address the kernel chooses, takes no
    // memory that anything else owns.
    let mapped = unsafe {
        libc::mmap(
            ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return None;
    }
    // The mapping is shared, so a child process would share the secret: it gets no mapping
    // instead, or the pages are given back and anonymous ones taken.
    // SAFETY: madvise marks the pages of the mapping just made and changes no content.
    if unsafe { libc::madvise(mapped, bytes, libc::MADV_DONTFORK) } != 0
        || !charge_pages(mapped, bytes)
    {
        // SAFETY: the mapping was just made and nothing refers to it.
        unsafe { libc::munmap(mapped, bytes) };
        return None;
    }
    NonNull::new(mapped.cast())
}

/// Charges every page of a new mapping of secret memory now, and returns whether the kernel took
/// them all. Since Linux commit 97d34aa65c29 it charges a page to the user's count against
/// RLIMIT_MEMLOCK at the page's first fault, not at mmap, and a fault over the limit is SIGBUS,
/// which would end the process at its first write to the secret. A write that the kernel itself
/// makes gets EFAULT instead, so the getrandom system call writes one byte into each page. It is
/// the raw call, since libc's function may be served by the vDSO in user space, where the write
/// would fault; the filter of `enter` allows it, and MADV_POPULATE_WRITE answers EINVAL on this
/// memory.
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

pub(crate) fn enter() -> Isolation {
    let whole_process = one_thread();
    #[cfg(target_os = "linux")]
    let empty_network = whole_process && enter_empty_network() && network_empty();
    #[cfg(target_os = "android")]
    let empty_network = false;
    let core_limit = super::unix::forbid_core_dumps();
    // SAFETY: PR_SET_DUMPABLE takes integers and touches no memory of this process.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    // Seccomp and Landlock require no_new_privs of an unprivileged process: no program it starts
    // can gain privileges, as a set-user-ID program would.
    // SAFETY: as above.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0 && !already_restricted() {
        #[cfg(target_os = "linux")]
        landlock_layer::restrict_self();
        seccomp::install();
        RESTRICTED_THREAD.set(true);
        if whole_process {
            RESTRICTED_PROCESS.store(true, Ordering::Relaxed);
        }
    }
    // SAFETY: PR_GET_DUMPABLE takes no pointer and returns the flag.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0;
    Isolation {
        // A pipe in core_pattern, as systemd-coredump and apport use, ignores RLIMIT_CORE: there
        // only a process that is not dumpable keeps a crash off the disk.
        no_core_dumps: core_limit && !dumpable,
        no_memory_reading: !dumpable,
        no_new_sockets: sockets_refused(),
        empty_network,
        no_file_changes: writing_refused(),
        whole_process,
    }
}

thread_local! {
    /// Whether this thread installed the filters.
    static RESTRICTED_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the filters were installed while the process had one thread, so that every thread has
/// them.
static RESTRICTED_PROCESS: AtomicBool = AtomicBool::new(false);

/// Whether the calling thread already holds the filters of an earlier call, its own or those of
/// the thread that started it: a second seccomp filter and a second Landlock layer would refuse
/// nothing more and use up the kernel's limits on both. Where this crate installs a seccomp
/// filter, the filter itself answers; elsewhere, what an earlier call of this thread or of the
/// whole process recorded. A filter that someone else installed, as every Android app and many
/// containers run under, is not this crate's and does not count.
fn already_restricted() -> bool {
    seccomp::held() || RESTRICTED_THREAD.get() || RESTRICTED_PROCESS.load(Ordering::Relaxed)
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

/// A network namespace of its own for the process, with only a loopback interface that stays down
/// and no route, in a user namespace of its own, without which an unprivileged process may not
/// make one; the kernel allows it only to a process of one thread, and where the system allows
/// user namespaces. Returns whether this call or an earlier one made it: the kernel refuses a
/// second one inside it, and a namespace that the process was started in can look empty while its
/// loopback is up and other processes share it. A refusal changes nothing.
#[cfg(target_os = "linux")]
fn enter_empty_network() -> bool {
    static MADE: AtomicBool = AtomicBool::new(false);
    // SAFETY: unshare takes flags only and touches no memory of this process.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } == 0 {
        MADE.store(true, Ordering::Relaxed);
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

/// A seccomp filter for the calling thread and the threads it starts afterwards. It refuses with
/// EACCES new sockets; io_uring, whose operations, a socket among them, run inside the kernel
/// without a call the filter would see; the calls that act on another process, which could take a
/// connected socket from it or drive it where Yama allows; every call that changes the file
/// system; and every ioctl but the terminal's, since an ioctl can change a file through a
/// descriptor open only for reading (fs-verity, encryption policies, btrfs subvolumes). It
/// answers ENOSYS to `openat2`, whose flags lie in a structure it cannot read, and to every call
/// newer than its table, so that the C library falls back to a call it reads and a later kernel's
/// call cannot get past it. Written for little-endian x86-64 and AArch64, whose numbers it holds.
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
    /// and another filter answers as it does; this crate's filter answers [`MARK`]. The four bytes
    /// read "SPC1".
    const MARK_OPTION: u32 = 0x5350_4331;
    /// The error number of that answer, beyond every one a kernel gives (MAX_ERRNO is 4095): the
    /// sign that a thread holds this crate's filter, whoever installed it.
    const MARK: u32 = 4001;

    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const REFUSE: u32 = libc::SECCOMP_RET_ERRNO | super::REFUSED as u32;
    const NO_SUCH_CALL: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
    const MARKED: u32 = libc::SECCOMP_RET_ERRNO | MARK;

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

    /// Returns `action` when the loaded value passes `test` with `value`, else goes on.
    fn answer_if(test: u16, value: u32, action: u32) -> [libc::sock_filter; 2] {
        [
            instruction(test, 0, 1, value),
            instruction(RETURN, 0, 0, action),
        ]
    }

    /// The filter, in which every test is followed by the answer it leads to, or skips a block
    /// that ends in answers, so that no jump goes further than the block it belongs to.
    fn program() -> Vec<libc::sock_filter> {
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
        // The mark, which a probe reads; every other prctl is allowed.
        program.extend([
            instruction(IF_EQUAL, 0, 4, calls::PRCTL),
            instruction(LOAD_WORD, 0, 0, argument(0)),
            instruction(IF_EQUAL, 0, 1, MARK_OPTION),
            instruction(RETURN, 0, 0, MARKED),
            instruction(RETURN, 0, 0, ALLOW),
        ]);
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

    /// Whether the calling thread holds this crate's filter, from its own call or from the thread
    /// that started it: only this filter answers [`MARK_OPTION`] with [`MARK`].
    pub(super) fn held() -> bool {
        // SAFETY: prctl takes integers; with an option that no kernel has it changes nothing and
        // touches no memory of this process.
        let result = unsafe { libc::prctl(MARK_OPTION as libc::c_int, 0, 0, 0, 0) };
        result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(MARK as i32)
    }

    pub(super) fn install() {
        let mut program = program();
        let filter = libc::sock_fprog {
            len: program.len() as u16,
            filter: program.as_mut_ptr(),
        };
        // SAFETY: the filter points to `len` instructions that live for the call; the kernel
        // copies them. It holds for the calling thread and the threads it starts afterwards.
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &raw const filter,
                0,
                0,
            )
        };
    }
}

/// No filter is written for other architectures: there Landlock alone restricts Linux.
#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
)))]
mod seccomp {
    pub(super) fn held() -> bool {
        false
    }

    pub(super) fn install() {}
}

/// A Landlock layer that handles every right to change the file system the kernel knows and grants
/// none, so that files cannot be opened for writing, created, renamed, removed or truncated and
/// devices take no ioctl, wherever they are; descriptors already open stay usable, and reading
/// stays unrestricted. From Linux 6.7 it also refuses TCP bind and connect, from Linux 6.12 a
/// connection to an abstract UNIX socket made outside the layer, and from Linux 7.1 a connection
/// to a UNIX socket by its path. Written with the `landlock` crate of the Landlock project, which
/// asks for the rights of Landlock's ABI 9 (Linux 7.1) and leaves out, on an older kernel, those it
/// does not know.
#[cfg(target_os = "linux")]
mod landlock_layer {
    use landlock::{ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, Scope};

    /// The newest Landlock ABI whose rights the layer asks for: that of Linux 7.1.
    const ASKED: ABI = ABI::V9;

    pub(super) fn restrict_self() {
        // A kernel without Landlock, or one that refuses the layer, leaves the thread as it was:
        // `enter` reads back what holds from the calls themselves, whatever this answers.
        let _ = Ruleset::default()
            .handle_access(AccessFs::from_write(ASKED))
            .and_then(|ruleset| ruleset.handle_access(AccessNet::from_all(ASKED)))
            .and_then(|ruleset| ruleset.scope(Scope::AbstractUnixSocket))
            .and_then(Ruleset::create)
            .and_then(|created| created.restrict_self());
    }
}
