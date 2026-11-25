//! What Linux and Android show of an isolated process: the checks and the roles of their own.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::mem::size_of;
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener};
use std::path::Path;
use std::ptr;

use secret_protection_core::{Isolation, Secret};

mod roles;
mod threads;

pub(crate) use roles::*;
pub(crate) use threads::*;

/// Requests of linux/fsverity.h, linux/fscrypt.h and linux/btrfs.h that change a file or make
/// a folder through a descriptor open only for reading.
const FS_IOC_ENABLE_VERITY: u32 = 0x4080_6685;
const FS_IOC_SET_ENCRYPTION_POLICY: u32 = 0x800c_6613;
const BTRFS_IOC_SUBVOL_CREATE: u32 = 0x5000_940e;

/// Calls that the filter refuses whatever their arguments, by libc's numbers, a source of
/// their own beside the filter's table, and by Linux 7.0's where libc 0.2.191 lacks them.
const REFUSED_CALLS: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_ptrace,
    libc::SYS_process_vm_writev,
    libc::SYS_pidfd_getfd,
    libc::SYS_kcmp,
    libc::SYS_process_madvise,
    libc::SYS_ioprio_set,
    libc::SYS_open_by_handle_at,
    // Linux on riscv64 and loongarch64 has no renameat, and no filter.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_unlinkat,
    libc::SYS_mkdirat,
    libc::SYS_mknodat,
    libc::SYS_linkat,
    libc::SYS_symlinkat,
    libc::SYS_truncate,
    libc::SYS_fallocate,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_fchown,
    libc::SYS_fchownat,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_fremovexattr,
    libc::SYS_utimensat,
    libc::SYS_mount,
    452, // fchmodat2
    463, // setxattrat
    466, // removexattrat
    469, // file_setattr
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    467, // open_tree_attr
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_sendmmsg,
    libc::SYS_msgget,
    libc::SYS_msgsnd,
    libc::SYS_msgrcv,
    libc::SYS_msgctl,
    libc::SYS_shmget,
    libc::SYS_shmat,
    libc::SYS_shmctl,
    libc::SYS_shmdt,
    libc::SYS_semget,
    libc::SYS_semop,
    libc::SYS_semtimedop,
    libc::SYS_semctl,
    libc::SYS_mq_open,
    libc::SYS_mq_unlink,
    libc::SYS_mq_timedsend,
    libc::SYS_mq_timedreceive,
    libc::SYS_mq_notify,
    libc::SYS_mq_getsetattr,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    libc::SYS_process_vm_readv,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_userfaultfd,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
];
/// The older calls that x86-64 has and AArch64 does not.
#[cfg(target_arch = "x86_64")]
const OLDER_CALLS: &[libc::c_long] = &[
    libc::SYS_creat,
    libc::SYS_rename,
    libc::SYS_unlink,
    libc::SYS_rmdir,
    libc::SYS_mkdir,
    libc::SYS_mknod,
    libc::SYS_link,
    libc::SYS_symlink,
    libc::SYS_chmod,
    libc::SYS_chown,
    libc::SYS_lchown,
    libc::SYS_utime,
    libc::SYS_utimes,
    libc::SYS_futimesat,
];
#[cfg(not(target_arch = "x86_64"))]
const OLDER_CALLS: &[libc::c_long] = &[];

/// In a thread of its own, so that the rest of the test process stays free: what the filter
/// and Landlock refuse is refused, and what a secret command needs still works.
pub(super) fn an_isolated_thread_is_refused_what_the_filter_names() {
    let folder = std::env::temp_dir().join(format!(
        "secret-protection-core-isolation-{}",
        std::process::id()
    ));
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&folder).unwrap();
    let file = folder.join("file");
    fs::write(&file, "public").unwrap();
    // Opened before: /dev/ptmx opens only for reading and writing.
    let (_controller, terminal) = pseudo_terminal();
    let mut idle = super::child("idle");
    let secret_memory = is_secret_memory(&Secret::with_capacity(1));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let unconnected = tcp_socket();
    let name = format!("secret-protection-core-{}", std::process::id());
    let _abstract_listener = abstract_listener(&name);
    let unix_unconnected = unix_socket();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (connected, peer) = UnixDatagram::pair().unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let isolation = Isolation::enter();
            crate::support::check_memory_reading(isolation);
            assert!(
                isolation.no_core_dumps && isolation.no_new_sockets && isolation.no_file_changes,
                "{isolation:?}"
            );
            assert!(!isolation.whole_process && !isolation.empty_network);
            // Confirmed for this thread alone: the rule for every thread refuses it, and says why.
            let wide = isolation
                .require_process_wide(&[secret_protection_core::Protection::NoNewSockets])
                .unwrap_err();
            for missing in [
                secret_protection_core::Protection::WholeProcess,
                secret_protection_core::Protection::NoNewSockets,
            ] {
                assert!(wide.missing.contains(&missing), "{:?}", wide.missing);
            }
            // A thread it starts holds its filter, which a further call finds although the
            // process has other threads: no filter is added.
            let filters = super::seccomp_filters();
            std::thread::scope(|inner| {
                inner.spawn(|| {
                    assert_eq!(Isolation::enter(), isolation);
                    assert_eq!(super::seccomp_filters(), filters);
                });
            });
            calls_are_refused(idle.id());
            other_processes_are_out_of_reach(idle.id());
            connecting_is_refused(&unconnected, listener.local_addr().unwrap().port());
            abstract_connecting_is_refused(&unix_unconnected, &name);
            sockets_opened_before_keep_only_their_connection(
                &udp,
                udp_receiver.local_addr().unwrap(),
                &connected,
                &peer,
            );
            the_dump_settings_cannot_be_undone();
            signals_reach_no_other_process(idle.id());
            speculation_is_limited_as_reported(isolation);
            files_stay_as_they_are(&folder, &file);
            what_a_secret_command_needs_still_works(&terminal, secret_memory);
            the_terminal_takes_no_typed_input(&terminal);
        });
    });
    // The rest of the process is not isolated.
    TcpListener::bind("127.0.0.1:0").unwrap();
    fs::rename(&file, folder.join("renamed")).unwrap();
    idle.stdin = None;
    idle.wait().unwrap();
    fs::remove_file(folder.join("renamed")).unwrap();
    fs::remove_dir(&folder).unwrap();
}

/// Installs a filter that allows every call, as the system or a container installs one of its
/// own before a program starts.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn install_a_foreign_filter() {
    let mut allow = [libc::sock_filter {
        code: 0x06, // BPF_RET | BPF_K
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }];
    let program = libc::sock_fprog {
        len: 1,
        filter: allow.as_mut_ptr(),
    };
    // SAFETY: prctl takes integers and, for the filter, a pointer to one instruction that
    // lives for the call; the kernel copies it.
    unsafe {
        assert_eq!(
            libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong
            ),
            0
        );
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &raw const program,
                0 as libc::c_ulong,
                0 as libc::c_ulong
            ),
            0
        );
    }
}

/// In a thread of its own: a first call without options refuses neither file locks nor
/// `sendmsg`; a call with them adds one filter that refuses both; further calls, with or
/// without them, add none and keep them.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn options_add_one_filter_at_most() {
    use secret_protection_core::{Options, Protection};
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let before = super::seccomp_filters();
            let plain = Isolation::enter();
            assert!(
                !plain.file_locks_refused && !plain.sendmsg_refused,
                "{plain:?}"
            );
            let one_more = before.map(|count| count + 1);
            assert_eq!(super::seccomp_filters(), one_more);
            let options = Options::new().refuse_file_locks().refuse_sendmsg();
            let required = [Protection::FileLocksRefused, Protection::SendmsgRefused];
            let strict = Isolation::enter_requiring(options, &required).unwrap();
            let two_more = before.map(|count| count + 2);
            assert_eq!(super::seccomp_filters(), two_more);
            assert_eq!(Isolation::enter_with(options), strict);
            assert_eq!(Isolation::enter(), strict);
            assert_eq!(super::seccomp_filters(), two_more);
            // Signals only to the process itself, with one more filter.
            let options = options.signals_to_self_only();
            let three_more = before.map(|count| count + 3);
            let own = Isolation::enter_with(options);
            assert!(own.signals_to_self_only, "{own:?}");
            // The Landlock scope is a claim of its own, by what the layer brought.
            assert_eq!(own.signals_within_layer, landlock_abi() >= 6, "{own:?}");
            assert_eq!(super::seccomp_filters(), three_more);
            // SAFETY: kill with signal 0 only checks; getppid and getpid take nothing. A
            // signal through a descriptor of a process is refused whatever the descriptor.
            unsafe {
                assert_eq!(
                    error_of(libc::kill(libc::getppid(), 0).into()),
                    Some(libc::EACCES)
                );
                assert_eq!(libc::kill(libc::getpid(), 0), 0);
                let own_process = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0);
                assert!(own_process >= 0);
                let sent = libc::syscall(libc::SYS_pidfd_send_signal, own_process, 0, 0, 0);
                assert_eq!(error_of(sent), Some(libc::EACCES));
            }
            let file = File::open("/dev/null").unwrap();
            // SAFETY: flock and fcntl take a descriptor and integers, or a struct that lives
            // for the call, and the filter refuses them before the kernel reads it.
            unsafe {
                let locked = libc::flock(file.as_raw_fd(), libc::LOCK_EX);
                assert_eq!(error_of(locked.into()), Some(libc::EACCES));
                // A lease is a lock that other processes see and wait for.
                let leased = libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK);
                assert_eq!(error_of(leased.into()), Some(libc::EACCES), "F_SETLEASE");
                // An owner of the descriptor would get its signals, whatever process it is.
                let owner = libc::fcntl(file.as_raw_fd(), libc::F_SETOWN, libc::getppid());
                assert_eq!(error_of(owner.into()), Some(libc::EACCES), "F_SETOWN");
                // `struct f_owner_ex`, F_OWNER_PID and F_SETOWN_EX of linux/fcntl.h, which
                // libc 0.2.191 lacks.
                #[repr(C)]
                struct OwnerEx {
                    kind: libc::c_int,
                    pid: libc::pid_t,
                }
                let named = OwnerEx {
                    kind: 1,
                    pid: libc::getppid(),
                };
                let owner = libc::fcntl(file.as_raw_fd(), 15, &raw const named);
                assert_eq!(error_of(owner.into()), Some(libc::EACCES), "F_SETOWN_EX");
                // F_SETSIG, and O_ASYNC, with which a terminal names its foreground group itself;
                // other flags still change.
                // F_SETSIG is 10; libc 0.2.191 names it on few systems.
                let signal = libc::fcntl(file.as_raw_fd(), 10, libc::SIGIO);
                assert_eq!(error_of(signal.into()), Some(libc::EACCES), "F_SETSIG");
                let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
                let made = libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_ASYNC);
                assert_eq!(error_of(made.into()), Some(libc::EACCES), "O_ASYNC");
                let plain = libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
                assert_eq!(plain, 0, "O_NONBLOCK");
                // F_SETDELEG of Linux 7.0, a delegated lease, which libc 0.2.191 lacks.
                let delegated = libc::fcntl(file.as_raw_fd(), 1040, 0);
                assert_eq!(error_of(delegated.into()), Some(libc::EACCES), "F_SETDELEG");
            }
            // The strict mode names what it lacks.
            let missing =
                Isolation::enter_requiring(Options::new(), &[Protection::MicrosoftSignedOnly]);
            assert_eq!(
                missing.map_err(|error| error.missing),
                Err(vec![Protection::MicrosoftSignedOnly])
            );
        });
    });
}

/// With the signal option alone, the fcntl rule refuses owners, F_SETSIG and O_ASYNC, and lets
/// locks and other flags through, which only the lock option would refuse.
pub(super) fn the_signal_option_alone_refuses_owners_and_async() {
    use secret_protection_core::Options;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let own = Isolation::enter_with(Options::new().signals_to_self_only());
            assert!(
                own.signals_to_self_only && !own.file_locks_refused,
                "{own:?}"
            );
            let file = File::open("/dev/null").unwrap();
            let fd = file.as_raw_fd();
            // SAFETY: fcntl and flock take a descriptor and integers.
            unsafe {
                let owner = libc::fcntl(fd, libc::F_SETOWN, libc::getppid());
                assert_eq!(error_of(owner.into()), Some(libc::EACCES), "F_SETOWN");
                // F_SETSIG is 10; libc 0.2.191 names it on few systems.
                assert_eq!(
                    error_of(libc::fcntl(fd, 10, libc::SIGIO).into()),
                    Some(libc::EACCES)
                );
                let flags = libc::fcntl(fd, libc::F_GETFL);
                let made = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_ASYNC);
                assert_eq!(error_of(made.into()), Some(libc::EACCES), "O_ASYNC");
                assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
                assert_eq!(libc::flock(fd, libc::LOCK_SH), 0, "flock");
            }
        });
    });
}

/// Two threads started side by side, neither from the other, each install a filter of their
/// own, once.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn sibling_threads_get_one_filter_each() {
    let before = super::seccomp_filters();
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                for _ in 0..3 {
                    assert!(Isolation::enter().no_file_changes);
                }
                assert_eq!(super::seccomp_filters(), before.map(|count| count + 1));
            });
        }
    });
    assert_eq!(super::seccomp_filters(), before);
}

/// Installs a filter that refuses to install another filter through prctl, with EPERM, and
/// allows every other call.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn install_a_filter_refusing_filters() {
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let mut program = [
        instruction(0x20, 0, 0, 0), // load the call's number
        instruction(0x15, 0, 3, libc::SYS_prctl as u32),
        instruction(0x20, 0, 0, 16), // load the option
        instruction(0x15, 0, 1, libc::PR_SET_SECCOMP as u32),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ALLOW),
    ];
    let filter = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: prctl takes integers and, for the filter, a pointer to instructions that live
    // for the call; the kernel copies them.
    unsafe {
        assert_eq!(
            libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong
            ),
            0
        );
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &raw const filter,
                0 as libc::c_ulong,
                0 as libc::c_ulong
            ),
            0
        );
    }
}

fn calls_are_refused(idle: u32) {
    for &number in REFUSED_CALLS.iter().chain(OLDER_CALLS) {
        // SAFETY: a descriptor of -1 and null pointers: without the filter, every call fails at
        // once and changes nothing.
        let result = unsafe { libc::syscall(number, -1_i64, 0_i64, 0_i64, 0_i64, 0_i64, 0_i64) };
        assert_eq!(error_of(result), Some(libc::EACCES), "call {number}");
    }
    let pid = libc::pid_t::try_from(idle).unwrap();
    // SAFETY: attaching passes no memory; it would stop the idle child, which the test ends.
    let attach = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0_i64, 0_i64) };
    assert_eq!(error_of(attach), Some(libc::EACCES), "ptrace");
    // openat2, whose flags the filter cannot read, and a call newer than Linux 7.0.
    for number in [437, 472] {
        // SAFETY: as above.
        let result = unsafe { libc::syscall(number, -1_i64, 0_i64, 0_i64, 0_i64) };
        assert_eq!(error_of(result), Some(libc::ENOSYS), "call {number}");
    }
}

/// Limits, scheduling and pages of another process are refused; this process's own stay open.
fn other_processes_are_out_of_reach(idle: u32) {
    let pid = libc::pid_t::try_from(idle).unwrap();
    // SAFETY: each call reads or writes only the values given, which live for the call; with
    // the filter the calls on the idle child change nothing, and without it they change only
    // that child, which the test ends.
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        let other = libc::syscall(
            libc::SYS_prlimit64,
            pid,
            libc::RLIMIT_CORE,
            0_i64,
            &raw mut limit,
        );
        assert_eq!(error_of(other), Some(libc::EACCES), "prlimit64");
        // The caller names itself 0; its own number is refused too, since a child of `fork`
        // inherits the filter and that number would name its parent.
        let own = libc::syscall(
            libc::SYS_prlimit64,
            0,
            libc::RLIMIT_CORE,
            0_i64,
            &raw mut limit,
        );
        assert_eq!(own, 0, "prlimit64 of 0");
        let by_number = libc::syscall(
            libc::SYS_prlimit64,
            libc::getpid(),
            libc::RLIMIT_CORE,
            0_i64,
            &raw mut limit,
        );
        assert_eq!(
            error_of(by_number),
            Some(libc::EACCES),
            "prlimit64 by number"
        );
        let lowered = libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, 19);
        assert_eq!(error_of(lowered.into()), Some(libc::EACCES), "setpriority");
        let mut cpus: libc::cpu_set_t = std::mem::zeroed();
        let size = size_of::<libc::cpu_set_t>();
        assert_eq!(libc::sched_getaffinity(0, size, &raw mut cpus), 0);
        let moved = libc::sched_setaffinity(pid, size, &raw const cpus);
        assert_eq!(
            error_of(moved.into()),
            Some(libc::EACCES),
            "sched_setaffinity"
        );
        assert_eq!(libc::sched_setaffinity(0, size, &raw const cpus), 0);
        let pages = libc::syscall(libc::SYS_move_pages, pid, 0_i64, 0_i64, 0_i64, 0_i64, 0_i64);
        assert_eq!(error_of(pages), Some(libc::EACCES), "move_pages");
        // Without the filter each fails otherwise, at its null or zero arguments.
        for number in [
            libc::SYS_migrate_pages,
            libc::SYS_get_robust_list,
            libc::SYS_sched_setparam,
            libc::SYS_sched_setscheduler,
            libc::SYS_sched_setattr,
        ] {
            let result = libc::syscall(number, pid, 0_i64, 0_i64, 0_i64);
            assert_eq!(error_of(result), Some(libc::EACCES), "call {number}");
        }
    }
}

/// A terminal opened before cannot be given typed input (TIOCSTI), which its shell would read
/// as the user's own keys.
fn the_terminal_takes_no_typed_input(terminal: &OwnedFd) {
    let key = b'x';
    // SAFETY: TIOCSTI reads the one byte given, which lives for the call.
    let typed = unsafe { libc::ioctl(terminal.as_raw_fd(), libc::TIOCSTI, &raw const key) };
    assert_eq!(error_of(typed.into()), Some(libc::EACCES));
}

/// From Linux 6.7 (Landlock's ABI 4), Landlock refuses to connect even a TCP socket opened
/// before, which the filter cannot refuse.
fn connecting_is_refused(socket: &OwnedFd, port: u16) {
    let abi = landlock_abi();
    // The filter refuses connect itself, before Landlock.
    let filtered = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: connect reads the address, which lives for the call.
    let result = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    let expected = (filtered || abi >= 4).then_some(libc::EACCES);
    assert_eq!(error_of(result.into()), expected, "Landlock {abi}");
}

/// From Linux 6.12 (Landlock's ABI 6), Landlock refuses to connect a UNIX socket opened
/// before to an abstract address on which a process outside the layer listens, which the
/// filter cannot refuse.
fn abstract_connecting_is_refused(socket: &OwnedFd, name: &str) {
    let abi = landlock_abi();
    // An abstract address starts with a zero byte, and its length counts only its name.
    let mut address = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };
    for (slot, &byte) in address.sun_path[1..].iter_mut().zip(name.as_bytes()) {
        *slot = byte as libc::c_char;
    }
    let length = size_of::<libc::sa_family_t>() + 1 + name.len();
    // SAFETY: connect reads `length` bytes of the address, which lives for the call.
    let result = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            libc::socklen_t::try_from(length).unwrap(),
        )
    };
    // The filter refuses connect itself, before Landlock's EPERM.
    let expected = if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        Some(libc::EACCES)
    } else {
        (abi >= 6).then_some(libc::EPERM)
    };
    assert_eq!(error_of(result.into()), expected, "Landlock {abi}");
}

/// A datagram with an address of its own is refused through a socket opened before, while a
/// socket connected before still sends to its peer.
fn sockets_opened_before_keep_only_their_connection(
    udp: &UdpSocket,
    to: std::net::SocketAddr,
    connected: &UnixDatagram,
    peer: &UnixDatagram,
) {
    let refused = udp
        .send_to(b"public", to)
        .map_err(|error| error.raw_os_error());
    assert_eq!(refused, Err(Some(libc::EACCES)));
    connected.send(b"public").unwrap();
    let mut received = [0; 6];
    assert_eq!(peer.recv(&mut received).unwrap(), 6);
}

/// The dump flag and the tracer setting, which would let other programs of the user read the
/// memory again, are refused.
fn the_dump_settings_cannot_be_undone() {
    for (option, value) in [
        (libc::PR_SET_DUMPABLE, 1),
        (libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY),
    ] {
        // SAFETY: prctl takes integers and touches no memory of this process.
        let result = unsafe {
            libc::prctl(
                option,
                value,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        assert_eq!(
            error_of(result.into()),
            Some(libc::EACCES),
            "option {option}"
        );
    }
    assert_eq!(
        // SAFETY: PR_GET_DUMPABLE takes only integer arguments.
        unsafe {
            libc::prctl(
                libc::PR_GET_DUMPABLE,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        },
        0
    );
}

/// From Linux 6.12 (Landlock's ABI 6), no signal reaches a process outside the layer, such as
/// the idle child started before.
fn signals_reach_no_other_process(idle: u32) {
    let abi = landlock_abi();
    let pid = libc::pid_t::try_from(idle).unwrap();
    // SAFETY: kill takes integers; SIGCONT leaves a running process as it is.
    let result = unsafe { libc::kill(pid, libc::SIGCONT) };
    let expected = (abi >= 6).then_some(libc::EPERM);
    assert_eq!(error_of(result.into()), expected, "Landlock {abi}");
}

/// `speculation_limited` says what the kernel reads back for both kinds of speculation, and a
/// disabled one cannot be enabled again.
fn speculation_is_limited_as_reported(isolation: Isolation) {
    let limited = [0 as libc::c_ulong, 1].iter().all(|&which| {
        // SAFETY: prctl takes integers and touches no memory of this process.
        let state = unsafe {
            libc::prctl(
                52,
                which,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if state > 0 && state & 8 != 0 {
            // SAFETY: as above; PR_SPEC_ENABLE.
            let enabled = unsafe {
                libc::prctl(
                    53,
                    which,
                    2 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            assert_eq!(
                error_of(enabled.into()),
                Some(libc::EPERM),
                "selector {which}"
            );
        }
        // Not affected; off for good; or off and not for a program to change.
        state == 0 || state > 0 && (state & 8 != 0 || state & 5 == 4)
    });
    assert_eq!(isolation.speculation_limited, limited, "{isolation:?}");
}

/// Started with a tracer attached, a process is not reported unreadable: the tracer keeps
/// reading. The test attaches to the first thread of the child, as a debugger would, without
/// stopping it, and lets the child enter the isolation: in the `traced` role from that thread,
/// in the `traced-sibling` role from another one, which shares the memory.
pub(super) fn a_traced_process_is_not_reported_unreadable(role: &str) {
    let mut process = super::child(role);
    let pid = libc::pid_t::try_from(process.id()).unwrap();
    // SAFETY: seizing passes no memory; the child keeps running.
    let seized = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0_i64, 0_i64) };
    assert_eq!(seized, 0, "{}", io::Error::last_os_error());
    process.stdin.as_mut().unwrap().write_all(b"x").unwrap();
    let mut line = String::new();
    BufReader::new(process.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    // A traced child would stop at a signal; SIGKILL ends it whatever its state.
    process.kill().unwrap();
    process.wait().unwrap();
    assert_eq!(line, "readable\n");
}

/// In a child process, which may lock all its memory: the answer agrees with the kernel's
/// count of locked memory, and the process still allocates and works.
pub(super) fn locking_all_memory_is_reported() {
    let output = super::child("locked").wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Starts this program again in `role` and expects it to end well.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn role_ends_well(role: &str) {
    let output = super::child(role).wait_with_output().unwrap();
    crate::support::role_ended(role, output.status, &output.stderr);
}

/// The Landlock ABI of the kernel; 0 or less without Landlock.
fn landlock_abi() -> libc::c_long {
    // SAFETY: with a null attribute and the version flag the call only returns a number.
    unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<u8>(),
            0_usize,
            1_u32,
        )
    }
}

/// A listener on an abstract UNIX address, made outside every Landlock layer.
fn abstract_listener(name: &str) -> UnixListener {
    let address = SocketAddr::from_abstract_name(name).unwrap();
    UnixListener::bind_addr(&address).unwrap()
}

/// A UNIX stream socket, not connected.
fn unix_socket() -> OwnedFd {
    // SAFETY: socket takes integers and returns a new descriptor, which nothing else owns.
    unsafe {
        let socket = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        assert!(socket >= 0);
        OwnedFd::from_raw_fd(socket)
    }
}

/// A TCP socket, not connected.
fn tcp_socket() -> OwnedFd {
    // SAFETY: socket takes integers and returns a new descriptor, which nothing else owns.
    unsafe {
        let socket = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        assert!(socket >= 0);
        OwnedFd::from_raw_fd(socket)
    }
}

fn files_stay_as_they_are(folder: &Path, file: &Path) {
    let refused = |result: io::Result<()>| {
        result.map_err(|error| error.raw_os_error()) == Err(Some(libc::EACCES))
    };
    assert!(refused(OpenOptions::new().write(true).open(file).map(drop)));
    assert!(refused(File::create(folder.join("new")).map(drop)));
    assert!(refused(fs::rename(file, folder.join("renamed"))));
    assert!(refused(fs::remove_file(file)));
    assert!(refused(fs::create_dir(folder.join("folder"))));
    // The filter refuses such an open itself: Landlock leaves a pipe open, which is no file of
    // a file system. On x86-64 also through open, which glibc's open does not issue; a mode of
    // 0 leaves the write bits to its flags.
    let (_reader, writer) = io::pipe().unwrap();
    let pipe = format!("/proc/self/fd/{}", writer.as_raw_fd());
    #[cfg(target_arch = "x86_64")]
    {
        let path = std::ffi::CString::new(pipe.as_str()).unwrap();
        // SAFETY: open reads the path, which lives for the call.
        let result = unsafe { libc::syscall(libc::SYS_open, path.as_ptr(), libc::O_WRONLY, 0_i64) };
        assert_eq!(error_of(result), Some(libc::EACCES), "open");
    }
    assert!(refused(OpenOptions::new().write(true).open(pipe).map(drop)));
    // Reading stays open; an ioctl that changes a file through a descriptor open for reading
    // is refused.
    assert_eq!(fs::read(file).unwrap(), b"public");
    let (file, folder) = (File::open(file).unwrap(), File::open(folder).unwrap());
    for (target, request) in [
        (&file, FS_IOC_ENABLE_VERITY),
        (&folder, FS_IOC_SET_ENCRYPTION_POLICY),
        (&folder, BTRFS_IOC_SUBVOL_CREATE),
    ] {
        // SAFETY: a null argument: without the filter, the call fails at once.
        let result =
            unsafe { libc::ioctl(target.as_raw_fd(), request.into(), ptr::null_mut::<u8>()) };
        assert_eq!(error_of(result.into()), Some(libc::EACCES), "{request:#x}");
    }
}

fn what_a_secret_command_needs_still_works(terminal: &OwnedFd, secret_memory: bool) {
    let terminal = terminal.as_raw_fd();
    // SAFETY: a termios and a winsize of zeros are valid; each call fills or reads the one it
    // is given, which lives for the call. tcgetattr and tcsetattr use the termios2 requests of
    // newer C libraries.
    unsafe {
        let mut settings: libc::termios = std::mem::zeroed();
        assert_eq!(libc::ioctl(terminal, libc::TCGETS, &raw mut settings), 0);
        assert_eq!(libc::tcgetattr(terminal, &raw mut settings), 0);
        for when in [libc::TCSANOW, libc::TCSADRAIN, libc::TCSAFLUSH] {
            assert_eq!(libc::tcsetattr(terminal, when, &raw const settings), 0);
        }
        let mut size: libc::winsize = std::mem::zeroed();
        assert_eq!(libc::ioctl(terminal, libc::TIOCGWINSZ, &raw mut size), 0);
    }
    // A secret still gets secret memory where the rest of the process gets it.
    assert_eq!(is_secret_memory(&Secret::with_capacity(1)), secret_memory);
    super::threads_and_a_work_area_still_work();
}

/// What a process of one thread reports on Linux, and the side effects of the empty network.
pub(super) fn expect_whole_process(isolation: Isolation) {
    crate::support::check_memory_reading(isolation);
    assert!(
        isolation.no_core_dumps
            && isolation.no_new_sockets
            && isolation.no_file_changes
            && isolation.no_new_programs,
        "{isolation:?}"
    );
    if isolation.empty_network {
        // No ID map is written in the new user namespace.
        // SAFETY: getuid and getgid only read.
        assert_eq!(unsafe { (libc::getuid(), libc::getgid()) }, (65534, 65534));
        let devices = fs::read_to_string("/proc/self/net/dev").unwrap();
        let interfaces: Vec<&str> = devices
            .lines()
            .skip(2)
            .filter_map(|line| line.split(':').next())
            .map(str::trim)
            .collect();
        assert_eq!(interfaces, ["lo"]);
        // System V objects and POSIX queues of its own.
        let parent = std::env::var_os(super::PARENT_IPC).unwrap();
        assert_ne!(
            fs::read_link("/proc/self/ns/ipc").unwrap().as_os_str(),
            parent
        );
    } else {
        // SAFETY: unshare takes flags only.
        let allowed = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } == 0;
        assert!(
            !allowed,
            "the system allows the empty network, which enter left out"
        );
        crate::support::skip(
            "this system allows no user namespace: the empty network is not checked",
        );
    }
}

/// The error number of a call that returned -1, or `None` for one that succeeded.
fn error_of(result: libc::c_long) -> Option<i32> {
    (result == -1).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// A pseudo-terminal: its controller and the terminal a secret command reads from.
fn pseudo_terminal() -> (OwnedFd, OwnedFd) {
    let (mut controller, mut terminal) = (-1, -1);
    // SAFETY: openpty writes the two descriptors it opens; no name, settings or size is
    // given.
    let opened = unsafe {
        libc::openpty(
            &mut controller,
            &mut terminal,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
        )
    };
    assert_eq!(opened, 0);
    // SAFETY: both descriptors were just opened, and nothing else owns them.
    unsafe {
        (
            OwnedFd::from_raw_fd(controller),
            OwnedFd::from_raw_fd(terminal),
        )
    }
}

/// Whether the pages of `secret` are secret memory, as /proc/self/maps names them.
fn is_secret_memory(secret: &Secret) -> bool {
    let address = secret.as_bytes().as_ptr() as usize;
    let maps = fs::read_to_string("/proc/self/maps").unwrap();
    maps.lines().any(|line| {
        let range = line
            .split(' ')
            .next()
            .and_then(|range| range.split_once('-'));
        let holds = range.is_some_and(|(start, end)| {
            let bound = |hex| usize::from_str_radix(hex, 16).unwrap();
            (bound(start)..bound(end)).contains(&address)
        });
        holds && line.ends_with("/secretmem (deleted)")
    })
}
