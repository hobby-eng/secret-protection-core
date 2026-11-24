//! The seccomp filter, for x86-64 and little-endian AArch64. It refuses (EACCES) new sockets and
//! io_uring, file system changes, ioctls other than the terminal's settings and size, new peers for
//! old sockets, System V IPC, POSIX queues, the keyring, `execve`, calls that read, compare, limit,
//! schedule or move the pages of another process, kernel interfaces a secret command never needs,
//! and the `prctl` options that undo the dump settings. Calls newer than its table get ENOSYS, so
//! libc falls back to ones the filter can check.

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
    /// prlimit64, sched_setparam, sched_setscheduler, sched_setaffinity, sched_setattr,
    /// move_pages, migrate_pages and get_robust_list, whose first argument is a process.
    pub(super) const ON_PROCESS: [u32; 8] = [302, 142, 144, 203, 314, 279, 256, 274];
    /// setpriority: allowed only for PRIO_PROCESS and the caller; PRIO_PGRP and PRIO_USER are
    /// refused whatever their second argument.
    pub(super) const SETPRIORITY: u32 = 141;
    /// open, whose flags are its second argument, and openat, whose flags are its third.
    pub(super) const OPENS: &[(u32, u32)] = &[(2, 1), (257, 2)];
    /// Refused whatever their arguments. Not ftruncate: it sizes the secret memory of every
    /// `Secret`, and it changes only a file already open for writing, which `write` changes
    /// anyway.
    pub(super) const REFUSED: &[u32] = &[
        41, 53, // socket, socketpair
        425, 426, 427, // io_uring_setup, io_uring_enter, io_uring_register
        101, 311, 438, // ptrace, process_vm_writev, pidfd_getfd
        312, 440, 251, // kcmp, process_madvise, ioprio_set
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
    /// prlimit64, sched_setparam, sched_setscheduler, sched_setaffinity, sched_setattr,
    /// move_pages, migrate_pages and get_robust_list, whose first argument is a process.
    pub(super) const ON_PROCESS: [u32; 8] = [261, 118, 119, 122, 274, 239, 238, 100];
    /// setpriority: allowed only for PRIO_PROCESS and the caller; PRIO_PGRP and PRIO_USER are
    /// refused whatever their second argument.
    pub(super) const SETPRIORITY: u32 = 140;
    /// openat, whose flags are its third argument.
    pub(super) const OPENS: &[(u32, u32)] = &[(56, 2)];
    /// Refused whatever their arguments. Not ftruncate: it sizes the secret memory of every
    /// `Secret`, and it changes only a file already open for writing, which `write` changes
    /// anyway.
    pub(super) const REFUSED: &[u32] = &[
        198, 199, // socket, socketpair
        425, 426, 427, // io_uring_setup, io_uring_enter, io_uring_register
        117, 271, 438, // ptrace, process_vm_writev, pidfd_getfd
        272, 440, 30,  // kcmp, process_madvise, ioprio_set
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
/// base with the filter's bits in its low eight bits, the sign that a thread holds this
/// crate's filter, whoever installed it. A filter that refuses other calls gets another base.
const MARK: u32 = 0xE00;
const MARK_BITS: u32 = 0xFF;
/// The options of a filter, as bits of the mark.
pub(super) const FILE_LOCKS: u32 = 1;
pub(super) const SENDMSG: u32 = 2;
pub(super) const SIGNALS: u32 = 4;
/// Bits that add no rule: the Landlock layer went in before this filter, and that layer
/// limits signals. The threads that inherit the filter read them from its mark.
pub(super) const LAYER: u32 = 8;
pub(super) const SCOPE: u32 = 16;

/// A second option that no kernel has, asked with a process number: a filter with the signal
/// rule answers whether the rule names that process. The four bytes read "SPC2".
const OWNER_OPTION: u32 = 0x5350_4332;
/// The error numbers of its two answers, which no kernel gives.
const NAMED: u32 = 0xD01;
const NOT_NAMED: u32 = 0xD00;

/// Whether the signal rule of the filter this thread holds names this very process. The filter
/// itself answers, the newest of this crate's on the thread: a rule that another thread holds,
/// or one inherited from the process this one was forked from, is never taken for it.
pub(super) fn names_this_process() -> bool {
    // SAFETY: getpid takes nothing; prctl takes integers, and with an option that no kernel
    // has it changes nothing and touches no memory of this process.
    let answer = unsafe {
        let own = libc::getpid() as libc::c_ulong;
        libc::prctl(
            OWNER_OPTION as libc::c_int,
            own,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    let named = i32::try_from(NAMED).ok();
    answer == -1 && std::io::Error::last_os_error().raw_os_error() == named
}
/// The lock commands of `fcntl`: F_SETLK, F_SETLKW, F_OFD_SETLK, F_OFD_SETLKW, and F_SETLEASE and
/// F_SETDELEG (Linux 7.0), whose lease other processes see in /proc/locks and wait for.
const LOCK_COMMANDS: [u32; 6] = [6, 7, 37, 38, 1024, 1040];
/// F_SETOWN, F_SETSIG and F_SETOWN_EX: with O_ASYNC the kernel signals the owner they name, which
/// can be any process of the user, without a signal call.
const OWNER_COMMANDS: [u32; 3] = [8, 10, 15];
/// F_SETFL, which sets O_ASYNC: on a terminal the kernel then makes the terminal's foreground
/// group the owner by itself, another process group.
const SET_FLAGS: u32 = 4;
/// PRIO_PROCESS of sys/resource.h: setpriority's second argument then names one process.
const PRIO_PROCESS: u32 = 0;

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
fn program(options: u32, own: libc::pid_t) -> Vec<libc::sock_filter> {
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
    // One block for fcntl, as its last answer allows every command it does not name.
    let mut refused_commands = Vec::new();
    if options & FILE_LOCKS != 0 {
        program.extend(answer_if(IF_EQUAL, calls::FLOCK, REFUSE));
        refused_commands.extend(LOCK_COMMANDS);
    }
    if options & SIGNALS != 0 {
        refused_commands.extend(OWNER_COMMANDS);
    }
    if !refused_commands.is_empty() {
        let mut commands = vec![instruction(LOAD_WORD, 0, 0, argument(1))];
        for command in refused_commands {
            commands.extend(answer_if(IF_EQUAL, command, REFUSE));
        }
        if options & SIGNALS != 0 {
            // F_SETFL with O_ASYNC is refused; F_SETFL without it, as for O_NONBLOCK, is not.
            commands.extend([
                instruction(IF_EQUAL, 0, 3, SET_FLAGS),
                instruction(LOAD_WORD, 0, 0, argument(2)),
                instruction(IF_ANY_BIT, 0, 1, libc::O_ASYNC as u32),
                instruction(RETURN, 0, 0, REFUSE),
            ]);
        }
        commands.push(instruction(RETURN, 0, 0, ALLOW));
        program.extend(for_call(calls::FCNTL, &commands));
    }
    if options & SENDMSG != 0 {
        program.extend(answer_if(IF_EQUAL, calls::SENDMSG, REFUSE));
    }
    if options & SIGNALS != 0 {
        // The process's own number, as `kill` and `tgkill` take it.
        let own = own as u32;
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
    // A call that acts on a process acts on the caller only, which names itself 0: a number would
    // still name this process in a child of `fork`, which inherits the filter.
    for number in calls::ON_PROCESS {
        program.extend(for_call(
            number,
            &[
                instruction(LOAD_WORD, 0, 0, argument(0)),
                instruction(IF_EQUAL, 1, 0, 0),
                instruction(RETURN, 0, 0, REFUSE),
                instruction(RETURN, 0, 0, ALLOW),
            ],
        ));
    }
    program.extend(for_call(
        calls::SETPRIORITY,
        &[
            instruction(LOAD_WORD, 0, 0, argument(0)),
            instruction(IF_EQUAL, 0, 2, PRIO_PROCESS),
            instruction(LOAD_WORD, 0, 0, argument(1)),
            instruction(IF_EQUAL, 1, 0, 0),
            instruction(RETURN, 0, 0, REFUSE),
            instruction(RETURN, 0, 0, ALLOW),
        ],
    ));
    // The mark, which a probe reads, and the two options that would let other programs of
    // the user read the memory again; every other prctl is allowed.
    let marked = libc::SECCOMP_RET_ERRNO | MARK | options;
    let mut prctl = vec![instruction(LOAD_WORD, 0, 0, argument(0))];
    prctl.extend(answer_if(IF_EQUAL, MARK_OPTION, marked));
    if options & SIGNALS != 0 {
        // Whom the rule above names: the process number comes as the second argument.
        prctl.extend([
            instruction(IF_EQUAL, 0, 4, OWNER_OPTION),
            instruction(LOAD_WORD, 0, 0, argument(1)),
            instruction(IF_EQUAL, 0, 1, own as u32),
            instruction(RETURN, 0, 0, libc::SECCOMP_RET_ERRNO | NAMED),
            instruction(RETURN, 0, 0, libc::SECCOMP_RET_ERRNO | NOT_NAMED),
        ]);
    }
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

/// Reads the rules marked on the calling thread or inherited from its creator. The marker
/// assumes other policies do not deliberately return this crate's response.
pub(super) fn held() -> Option<u32> {
    // SAFETY: prctl takes integers; with an option that no kernel has it changes nothing and
    // touches no memory of this process.
    let result = unsafe {
        libc::prctl(
            MARK_OPTION as libc::c_int,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    let error = std::io::Error::last_os_error().raw_os_error()?;
    let error = u32::try_from(error).ok()?;
    (result == -1 && error & !MARK_BITS == MARK).then_some(error & MARK_BITS)
}

/// Installs the filter with the bits `options` for the calling thread and the threads it
/// starts afterwards, and returns the bits of the filter it holds now.
pub(super) fn install(options: u32) -> Option<u32> {
    // SAFETY: getpid takes nothing and touches no memory.
    let own = unsafe { libc::getpid() };
    let mut program = program(options, own);
    let filter = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: the filter points to `len` instructions that live for the call; the kernel
    // copies them. It holds for the calling thread and the threads it starts afterwards.
    let installed = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            &raw const filter,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } == 0;
    if installed { held() } else { None }
}
