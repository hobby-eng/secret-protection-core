//! Linux and Android: secret memory, the seccomp filter, Landlock, namespaces, and the probes that
//! check them.
//!
//! An Android app's own seccomp policy kills the process on calls it doesn't expect, so on Android
//! this module skips secret memory, Landlock, `unshare` and io_uring.
#![allow(
    unsafe_code,
    reason = "memfd_secret, ftruncate, mmap, madvise, getrandom, munmap, sysconf, prctl, unshare, \
              socket, open, close, mlockall, pthread_atfork and the io_uring and Landlock calls \
              are foreign functions, and a new mapping is written through a raw pointer"
)]

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::ptr::NonNull;
use std::sync::OnceLock;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::protect::{Findings, Isolation, Options};
use crate::{Outcome, Protection};

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
    // No `fork` while the descriptor is open: its child would keep it, and close-on-exec helps
    // only a child that starts a program.
    let _gate = fork_gate::Gate::take()?;
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
    mappings::remember(start);
    Some(start)
}

mod mappings;

#[cfg(target_os = "linux")]
pub(super) use mappings::forget as forget_secret;
pub(crate) use mappings::shared_mappings;

/// Keeps `fork` out while a descriptor of secret memory is open. A child made by `fork` at that
/// moment would inherit the descriptor and could map the pages a secret is written to later.
/// `fork` waits in its prepare handler; a child made by a raw `clone` call is not covered. A
/// process that already had other threads when the gate was first asked for gets none, and so
/// no secret memory.
#[cfg(target_os = "linux")]
mod fork_gate {
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Once, OnceLock};
    use std::time::{Duration, Instant};

    static HELD: AtomicBool = AtomicBool::new(false);
    /// How long a secret waits for a `fork` that holds the gate. A fork handler of the program's
    /// own may wait for a lock that the thread making the secret holds: past this, the secret
    /// takes anonymous pages instead of waiting for ever.
    const PATIENCE: Duration = Duration::from_millis(100);

    use crate::os::unix::forks::pthread_atfork;

    /// A spin lock: the handlers of `fork` may do only what a signal handler may.
    unsafe extern "C" fn hold() {
        while HELD
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // SAFETY: sched_yield takes nothing and touches no memory.
            unsafe { libc::sched_yield() };
        }
    }

    unsafe extern "C" fn release() {
        HELD.store(false, Ordering::Release);
    }

    /// Whether `fork` takes the gate. Its handlers are registered once, and only while the
    /// process has one thread: a `fork` that another thread had already begun runs no handler
    /// registered after it started, and would pass the gate. The caller blocks signals, so no
    /// handler starts a thread in between.
    fn registered() -> bool {
        static REGISTERING: Once = Once::new();
        static REGISTERED: OnceLock<bool> = OnceLock::new();
        REGISTERING.call_once(|| {
            // SAFETY: registers three functions that live as long as the program.
            let done = super::one_thread()
                && unsafe { pthread_atfork(Some(hold), Some(release), Some(release)) } == 0;
            let _ = REGISTERED.set(done);
        });
        REGISTERED.get().copied().unwrap_or(false)
    }

    /// The gate, held until dropped. Signals are blocked meanwhile: a handler that forked on
    /// this thread would wait for the gate its own thread holds.
    pub(super) struct Gate(libc::sigset_t);

    impl Gate {
        /// `None` when `fork` does not take the gate: then no secret memory is taken.
        pub(super) fn take() -> Option<Self> {
            // SAFETY: the two sets are filled by the calls before they are read.
            let before = unsafe {
                let mut all: libc::sigset_t = std::mem::zeroed();
                let mut before: libc::sigset_t = std::mem::zeroed();
                libc::sigfillset(&mut all);
                // A handler that forked on this thread would wait for the gate it holds: where
                // signals cannot be blocked, no secret memory is taken.
                if libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut before) != 0 {
                    return None;
                }
                before
            };
            if !registered() {
                // SAFETY: gives back the signal mask replaced above.
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &before, ptr::null_mut()) };
                return None;
            }
            let deadline = Instant::now() + PATIENCE;
            while HELD
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                if Instant::now() >= deadline {
                    // SAFETY: gives back the signal mask replaced above.
                    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &before, ptr::null_mut()) };
                    return None;
                }
                // SAFETY: sched_yield takes nothing and touches no memory.
                unsafe { libc::sched_yield() };
            }
            Some(Self(before))
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            // SAFETY: gives back the gate this value holds and the signal mask it replaced.
            unsafe {
                release();
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, ptr::null_mut());
            }
        }
    }
}

/// Register the memory fork gate before this library introduces a waiter thread.
#[cfg(target_os = "linux")]
pub(super) fn prepare_secret_pages() {
    if one_thread() {
        drop(fork_gate::Gate::take());
    }
}

/// Touches every page of new secret memory, so the lock limit is charged now. Newer kernels charge
/// it at the first fault and send SIGBUS when over the limit, which would kill the process at its
/// first write. A byte written by `getrandom` from inside the kernel only gets EFAULT. It is the raw
/// syscall because the vDSO version would fault in user space.
#[cfg(target_os = "linux")]
fn charge_pages(mapped: *mut libc::c_void, bytes: usize) -> bool {
    for offset in (0..bytes).step_by(super::unix::page_size()) {
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

pub(crate) fn enter_granting(options: Options, folders: &[&crate::WritableFolder]) -> Isolation {
    use Protection as P;
    use std::os::fd::AsFd;
    let _entering = Entering::take();
    // Granted only while each is still the new, empty folder made, and only by a first layer.
    let asked = !folders.is_empty();
    let fresh: Vec<_> = if folders.iter().all(|folder| folder.still_new()) {
        folders.iter().map(|folder| folder.as_fd()).collect()
    } else {
        Vec::new()
    };
    // A program isolates itself early, often while it has one thread: the gate of secret
    // memory is asked for now, for the secrets that threads make later.
    #[cfg(target_os = "linux")]
    prepare_secret_pages();
    let whole_process = one_thread();
    // TSYNC only matters with other threads, whose restrictions it changes in mid-work. Not on
    // Android: an app's own threads (Binder, the runtime's) would lose what the filter refuses.
    let sync = cfg!(target_os = "linux") && options.all_threads && !whole_process;
    // Before the user namespace: once in one, every process of the user holds CAP_SYS_PTRACE
    // there, which passes Yama, and only a cleared dumpable flag still keeps it out.
    let core_limit = super::unix::forbid_core_dumps();
    // SAFETY: PR_SET_DUMPABLE takes integers and touches no memory of this process. Once the
    // filter holds, it refuses this call, and the flag stays 0.
    unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    // A host policy can refuse that call: without the flag read back as cleared, no namespace.
    #[cfg(target_os = "linux")]
    // SAFETY: PR_GET_DUMPABLE takes no pointer and returns the flag.
    let undumpable = unsafe {
        libc::prctl(
            libc::PR_GET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } == 0;
    #[cfg(target_os = "linux")]
    let empty_network = whole_process && undumpable && enter_own_namespaces() && network_empty();
    let speculation = limit_speculation();
    let memory = lock_memory(options.lock_all);
    let wanted = (u32::from(options.file_locks) * seccomp::FILE_LOCKS)
        | (u32::from(options.sendmsg) * seccomp::SENDMSG)
        | (u32::from(options.own_signals) * seccomp::SIGNALS);
    // Seccomp and Landlock require no_new_privs of an unprivileged process: no program it starts
    // can gain privileges, as a set-user-ID program would.
    // SAFETY: as above.
    let restricted = if unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } == 0
    {
        restrict(whole_process, wanted, &fresh, sync)
    } else {
        Restricted {
            held: seccomp::held(),
            granted: false,
            filter_synced: false,
            layer_synced: false,
        }
    };
    let held = restricted.held;
    // How far the per-thread restrictions reach: the filter, and the layer where there is one.
    let filter_wide = whole_process || restricted.filter_synced;
    let layer_wide = whole_process || restricted.layer_synced;
    let layered = layer_bits(held) & seccomp::LAYER != 0;
    let folders_held = held.is_some_and(|rules| rules & seccomp::FOLDERS != 0);
    // SAFETY: PR_GET_DUMPABLE takes no pointer and returns the flag.
    let dumpable = unsafe {
        libc::prctl(
            libc::PR_GET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } != 0;
    let self_only =
        held.is_some_and(|rules| rules & seccomp::SIGNALS != 0) && seccomp::names_this_process();
    let mut found = Findings::new();
    // A pipe in core_pattern, as systemd-coredump and apport use, ignores RLIMIT_CORE: there
    // only a process that is not dumpable keeps a crash off the disk.
    found.check(P::NoCoreDumps, core_limit && !dumpable, true);
    // A tracer attached before the call keeps reading, whatever the flag says. One outside
    // the PID namespace of /proc shows as none there.
    let reading = match (dumpable, traced()) {
        (false, Some(false)) if tracers_show() => Outcome::Confirmed,
        (false, Some(false) | None) => Outcome::Unknown,
        _ => Outcome::Refused,
    };
    found.set(P::NoMemoryReading, reading, true);
    let filter = held.is_some();
    found.set(
        P::NoNewSockets,
        probed(filter, sockets_refused()),
        filter_wide,
    );
    #[cfg(target_os = "linux")]
    found.check(P::EmptyNetwork, empty_network, true);
    // Only the filter refuses every change of a file, by the calls and the flags of an open;
    // Landlock alone leaves modes, owners, extended attributes and times.
    // With folders, the filter alone lets writes through: only where the layer went too.
    found.check(
        P::NoFileChanges,
        held.is_some() && writing_refused(),
        filter_wide && (!folders_held || layer_wide),
    );
    found.set(P::SpeculationLimited, speculation, whole_process);
    found.set(
        P::NoNewPrograms,
        probed(filter, programs_refused()),
        filter_wide,
    );
    found.check(
        P::WholeProcess,
        filter_wide && (!layered || layer_wide),
        true,
    );
    let rule = |bit: u32| held.is_some_and(|rules| rules & bit != 0);
    found.set(
        P::FileLocksRefused,
        option_probed(
            options.file_locks,
            rule(seccomp::FILE_LOCKS),
            file_locks_refused(),
        ),
        filter_wide,
    );
    found.set(
        P::SendmsgRefused,
        option_probed(options.sendmsg, rule(seccomp::SENDMSG), sendmsg_refused()),
        filter_wide,
    );
    found.option(
        P::SignalsToSelfOnly,
        options.own_signals,
        self_only,
        filter_wide,
    );
    #[cfg(target_os = "linux")]
    found.check(
        P::SignalsWithinLayer,
        layer_bits(held) & seccomp::SCOPE != 0,
        layer_wide,
    );
    found.set(P::MemoryLocked, memory, true);
    // This call's layer took the folders, which keeps writes beneath them, and the filter lets
    // them through in the granted forms.
    found.option(
        P::FolderWrites,
        asked,
        restricted.granted && rule(seccomp::FOLDERS),
        filter_wide && layer_wide,
    );
    found.finish()
}

/// What a refused probe proves. With this crate's filter in place it confirms the protection.
/// Without it the refusal is someone else's policy, which may refuse the probe and little else:
/// unknown.
fn probed(filter: bool, refused: bool) -> Outcome {
    match (refused, filter) {
        (true, true) => Outcome::Confirmed,
        (true, false) => Outcome::Unknown,
        (false, _) => Outcome::Refused,
    }
}

/// As [`probed`] for an option: `rule` says whether the filter this thread holds has its rule.
/// Neither a rule nor a refusal means refused when the call asked, and not requested otherwise.
fn option_probed(asked: bool, rule: bool, refused: bool) -> Outcome {
    match (rule, refused, asked) {
        (true, true, _) => Outcome::Confirmed,
        (true, false, _) | (false, true, _) => Outcome::Unknown,
        (false, false, true) => Outcome::Refused,
        (false, false, false) => Outcome::NotRequested,
    }
}

/// The byte that says this process locked all its memory. It lies on a page that a child made
/// by `fork` gets as zeros (`MADV_WIPEONFORK`), since the child inherits no lock. The process's
/// number would not tell them apart: a child in a PID namespace of its own can have its
/// parent's. `None` where the system gives no such page.
fn lock_mark() -> Option<&'static AtomicU8> {
    static PAGE: OnceLock<usize> = OnceLock::new();
    let page = *PAGE.get_or_init(|| {
        let bytes = super::unix::page_size();
        // SAFETY: the mapping is new, private and anonymous, and madvise and munmap name it whole.
        unsafe {
            let page = libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if page == libc::MAP_FAILED {
                return 0;
            }
            if libc::madvise(page, bytes, libc::MADV_WIPEONFORK) != 0 {
                libc::munmap(page, bytes);
                return 0;
            }
            page as usize
        }
    });
    // SAFETY: the page lives as long as the process and is reached only as this atomic byte.
    (page != 0).then(|| unsafe { &*(page as *const AtomicU8) })
}

/// Keeps every page of the process, now and later, out of swap when `asked`, and says whether
/// the process holds such a lock, from this call or an earlier one. Pages are locked as they are
/// first touched (`MCL_ONFAULT`), so a large reservation costs nothing until it is used.
fn lock_memory(asked: bool) -> Outcome {
    /// Set when all memory was locked where no mark could be made.
    static UNMARKED: AtomicBool = AtomicBool::new(false);
    let mark = lock_mark();
    // SAFETY: mlockall takes flags and touches no memory of this process.
    let locked = asked
        && unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT) } == 0;
    if locked {
        match mark {
            Some(mark) => mark.store(1, Ordering::Relaxed),
            None => UNMARKED.store(true, Ordering::Relaxed),
        }
    }
    let marked = mark.map(|mark| mark.load(Ordering::Relaxed) == 1);
    lock_outcome(asked, locked, marked, UNMARKED.load(Ordering::Relaxed))
}

/// What a call says of the lock of all memory. `locked` is this call's own lock; `marked` is
/// the mark's answer where there is a mark; `unmarked` says that a lock was once taken without
/// one, in this process or in the one it was forked from, which nothing here can tell apart.
/// A refused call leaves an earlier lock as it was.
fn lock_outcome(asked: bool, locked: bool, marked: Option<bool>, unmarked: bool) -> Outcome {
    if locked || marked == Some(true) {
        Outcome::Confirmed
    } else if marked.is_none() && unmarked {
        Outcome::Unknown
    } else if asked {
        Outcome::Refused
    } else {
        Outcome::NotRequested
    }
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
    /// The bits of the Landlock layer this thread applied: [`seccomp::LAYER`], and
    /// [`seccomp::SCOPE`] when it limits signals.
    static LAYERED_THREAD: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Those bits for a layer applied while the process had one thread, which every thread holds.
#[cfg(target_os = "linux")]
static LAYERED_PROCESS: AtomicU32 = AtomicU32::new(0);

/// The bits of a filter that reached every thread, by TSYNC or by going in while the process had
/// one thread, with [`ON_EVERY_THREAD`] set, and in the high half the process it holds for; 0
/// before. A later call that holds the same filter installs it again on no thread. A child of
/// `fork` inherits the record but not its truth: its threads may hold a filter that names the
/// parent, so a record of another process counts for nothing.
#[cfg(target_has_atomic = "64")]
static PROCESS_FILTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(target_has_atomic = "64")]
const ON_EVERY_THREAD: u32 = 1 << 31;

/// Whether [`PROCESS_FILTER`] records `rules` on every thread of this process. Without 64-bit
/// atomics there is no record, and a filter is never taken to be on every thread by it.
fn recorded(rules: u32) -> bool {
    #[cfg(target_has_atomic = "64")]
    return PROCESS_FILTER.load(Ordering::Relaxed) == on_every_thread(rules);
    #[cfg(not(target_has_atomic = "64"))]
    {
        let _ = rules;
        false
    }
}

/// Records `rules` as on every thread of this process.
fn record(rules: u32) {
    #[cfg(target_has_atomic = "64")]
    PROCESS_FILTER.store(on_every_thread(rules), Ordering::Relaxed);
    #[cfg(not(target_has_atomic = "64"))]
    let _ = rules;
}

/// The record of [`PROCESS_FILTER`] for `rules` in this process.
#[cfg(target_has_atomic = "64")]
fn on_every_thread(rules: u32) -> u64 {
    // SAFETY: getpid takes nothing and touches no memory.
    let own = unsafe { libc::getpid() };
    u64::from(own.unsigned_abs()) << 32 | u64::from(rules | ON_EVERY_THREAD)
}

/// The Landlock bits the calling thread holds: from the mark of the filter that went in after
/// the layer, which the threads it starts answer too, or from what the thread or the process
/// recorded. Only a layer the kernel took is ever recorded.
fn layer_bits(held: Option<u32>) -> u32 {
    let marked = held.unwrap_or(0) & (seccomp::LAYER | seccomp::SCOPE | seccomp::FOLDERS);
    #[cfg(target_os = "linux")]
    return marked | LAYERED_THREAD.get() | LAYERED_PROCESS.load(Ordering::Relaxed);
    #[cfg(target_os = "android")]
    marked
}

/// What [`restrict`] did: the filter the calling thread holds, whether this call's layer took
/// the folders, and whether the filter and the layer went onto every thread at once.
struct Restricted {
    held: Option<u32>,
    granted: bool,
    filter_synced: bool,
    layer_synced: bool,
}

/// Gives this thread the Landlock layer and the seccomp filter, if it doesn't have them yet, and
/// reports what it holds then. Only what the kernel accepted is recorded, so a refused layer or
/// filter is tried again by the next call; a filter goes in only when it adds a bit. A filter
/// installed by someone else (Android, containers) doesn't count. With `sync`, both go onto every
/// thread (TSYNC), the ones already there again too, so that the other threads get them.
fn restrict(
    whole_process: bool,
    wanted: u32,
    folders: &[std::os::fd::BorrowedFd<'_>],
    sync: bool,
) -> Restricted {
    let held = seccomp::held();
    let layer = layer_bits(held);
    // Whether this call's layer took `folders`: an earlier layer may hold other folders.
    // A layer again for `sync` only where it can reach every thread, when none did yet, and when
    // the one there grants no folder: one without them would close the folders, as layers only
    // narrow. Each layer counts against the kernel's limit of 16.
    #[cfg(target_os = "linux")]
    let process_layer = LAYERED_PROCESS.load(Ordering::Relaxed) & seccomp::LAYER != 0;
    #[cfg(target_os = "linux")]
    let again = sync && layer & seccomp::FOLDERS == 0 && !process_layer && landlock_layer::syncs();
    // The layer's TSYNC replaces every other thread's layer for good, and the filter's TSYNC
    // after it is refused where a thread holds a filter the caller's does not descend from. A
    // filter that allows everything goes onto every thread first, which the kernel refuses in
    // just that case, with nothing put in: then nothing goes onto the other threads.
    #[cfg(target_os = "linux")]
    let sync = sync
        && !((layer & seccomp::LAYER == 0 || again)
            && landlock_layer::syncs()
            && !seccomp::share_filters());
    #[cfg(target_os = "linux")]
    let again = again && sync;
    #[cfg(target_os = "linux")]
    let (layer, granted, layer_synced) = if layer & seccomp::LAYER == 0 || again {
        // Folders only into a first layer, with a first filter: an earlier one keeps them closed.
        let folders = if held.is_none() && layer & seccomp::LAYER == 0 {
            folders
        } else {
            &[]
        };
        let first = layer & seccomp::LAYER == 0;
        let (applied, synced) = landlock_layer::restrict_self(folders, sync, first);
        let applied = applied | (layer & (seccomp::LAYER | seccomp::SCOPE | seccomp::FOLDERS));
        LAYERED_THREAD.set(applied);
        if whole_process || synced {
            LAYERED_PROCESS.store(applied, Ordering::Relaxed);
        }
        (
            applied,
            applied & seccomp::FOLDERS != 0 && !folders.is_empty(),
            synced || process_layer,
        )
    } else {
        (layer, false, process_layer)
    };
    #[cfg(target_os = "android")]
    let (granted, layer_synced) = {
        let _ = (whole_process, folders);
        (false, false)
    };
    let rules = held.unwrap_or(0) | wanted | layer;
    // A signal rule inherited from the process this one was forked from names that process:
    // a call that asks for the protection gets a filter of this process's own.
    let inherited = wanted & seccomp::SIGNALS != 0
        && held.is_some_and(|rules| rules & seccomp::SIGNALS != 0)
        && !seccomp::names_this_process();
    // A filter goes in when it adds a rule, or for `sync` when this one has not reached every
    // thread yet; stacked filters all run on every call, up to the kernel's limit.
    let needed = held != Some(rules) || inherited;
    let everywhere = recorded(rules);
    // The filter's marks and folder rules speak for the layer: it goes onto every thread only
    // where the layer did too, or where this thread holds none, never onto threads without it.
    let sync = sync && (layer & seccomp::LAYER == 0 || layer_synced);
    let (held, filter_synced) = if !needed && (everywhere || !sync) {
        (held, everywhere)
    } else {
        let (installed, synced) = seccomp::install(rules, sync, needed);
        if installed == Some(rules) && (synced || whole_process) {
            record(rules);
        }
        // Only this call's TSYNC: a filter put in again for a rule inherited from the process this
        // one was forked from reaches the calling thread alone.
        (installed.or(held), synced)
    };
    Restricted {
        held,
        granted,
        filter_synced,
        layer_synced,
    }
}

/// `prctl` options of linux/prctl.h for the processor's speculation, written out because libc
/// gives them other types on Linux and Android.
const GET_SPECULATION: libc::c_int = 52;
const SET_SPECULATION: libc::c_int = 53;
/// Speculative store bypass (Spectre variant 4) and indirect branch speculation (variant 2, from
/// other processes).
const SPECULATIONS: [libc::c_ulong; 2] = [0, 1];
/// Bits of the kernel's answer: a program may change it; off; off for good.
const SPEC_PRCTL: libc::c_int = 1 << 0;
const SPEC_DISABLE: libc::c_int = 1 << 2;
const SPEC_FORCE_DISABLE: libc::c_int = 1 << 3;

/// What the kernel says of one kind of speculation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Speculation {
    /// Off for good, kept off by the system for every program, or the processor is not affected.
    Off,
    /// On, or off in a way the program could undo.
    On,
    /// The query failed, for example with ENODEV on a CPU without this control.
    Unknown,
}

/// Reads an answer of PR_GET_SPECULATION_CTRL; `None` stands for a refusal of the call.
fn speculation_state(answer: Option<libc::c_int>) -> Speculation {
    match answer {
        None => Speculation::Unknown,
        // No bit: not affected. Off without the bit for a program's control: the system's doing.
        Some(0) => Speculation::Off,
        Some(state) if state & SPEC_FORCE_DISABLE != 0 => Speculation::Off,
        Some(state) if state & SPEC_DISABLE != 0 && state & SPEC_PRCTL == 0 => Speculation::Off,
        Some(_) => Speculation::On,
    }
}

/// Requests permanent disabling of both speculation mechanisms. A state that is enabled
/// or can be re-enabled gives `Refused`; otherwise a failed query gives `Unknown`.
fn limit_speculation() -> Outcome {
    let states = SPECULATIONS.map(|which| {
        // SAFETY: prctl takes integers and touches no memory of this process.
        unsafe {
            libc::prctl(
                SET_SPECULATION,
                which,
                SPEC_FORCE_DISABLE as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            );
        }
        // SAFETY: as above.
        let state = unsafe {
            libc::prctl(
                GET_SPECULATION,
                which,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        speculation_state((state >= 0).then_some(state))
    });
    if states.contains(&Speculation::On) {
        Outcome::Refused
    } else if states.contains(&Speculation::Unknown) {
        Outcome::Unknown
    } else {
        Outcome::Confirmed
    }
}

/// Whether any thread of the process has a tracer, such as a debugger it was started under: a
/// tracer attaches to single threads, and each of them shares the memory. `None` when the threads
/// or their status cannot be read.
fn traced() -> Option<bool> {
    // A listing can skip a thread that another ends meanwhile: it counts only when it read as
    // many threads as the kernel counts before and after it, else it is read again.
    for _ in 0..3 {
        let before = thread_count()?;
        let mut any = false;
        let mut read = 0;
        for task in std::fs::read_dir("/proc/self/task").ok()? {
            let status = match std::fs::read_to_string(task.ok()?.path().join("status")) {
                Ok(status) => status,
                // A thread that ended since it was listed.
                Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                    continue;
                }
                Err(_) => return None,
            };
            read += 1;
            let tracer = status
                .lines()
                .find_map(|line| line.strip_prefix("TracerPid:"))?;
            any |= tracer.trim() != "0";
        }
        if read == before && thread_count()? == before {
            return Some(any);
        }
    }
    None
}

/// Whether every tracer shows in /proc: only in the first PID namespace of the system. In a
/// namespace of its own, as in a container, a tracer outside it reads as no tracer. The number
/// is the kernel's PROC_PID_INIT_INO; a kernel that changed it would read as not the first.
fn tracers_show() -> bool {
    std::fs::read_link("/proc/self/ns/pid").is_ok_and(|name| name.as_os_str() == "pid:[4026531836]")
}

/// Whether the process has one thread: only then may it enter a user namespace of its own, and
/// only then do the filters, which a thread passes on to the threads it starts, hold for the whole
/// process. An Android app always has other threads.
pub(crate) fn one_thread() -> bool {
    #[cfg(target_os = "linux")]
    return thread_count() == Some(1);
    #[cfg(target_os = "android")]
    false
}

/// How many threads the process has, as the kernel counts them ("Threads:" of
/// /proc/self/status): a listing of /proc/self/task can miss one that another ends meanwhile.
fn thread_count() -> Option<usize> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))?
        .trim()
        .parse()
        .ok()
}

/// One isolation of the process at a time: two at once would put the layer and the filter of
/// one over the other's. A flag, not a lock, carrying the mark of the process that holds it, so
/// that a child of `fork` made while another thread held it takes it over instead of waiting
/// forever.
struct Entering;

static ENTERING: super::unix::forks::AtomicMark = super::unix::forks::AtomicMark::new(0);

impl Entering {
    fn take() -> Self {
        let own = super::unix::forks::mark();
        loop {
            let holder = ENTERING.load(Ordering::Acquire);
            let free = holder == 0 || holder != own;
            if free
                && ENTERING
                    .compare_exchange(holder, own, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return Self;
            }
            std::thread::yield_now();
        }
    }
}

impl Drop for Entering {
    fn drop(&mut self) {
        ENTERING.store(0, Ordering::Release);
    }
}

/// Moves the process into its own empty network namespace and its own IPC namespace, inside a new
/// user namespace (needed without root), all in one call: a system such as Ubuntu takes the
/// capabilities of an unprivileged process once it is inside, so a second call would be refused.
/// The kernel allows this only for a single-threaded process. Returns whether the namespaces
/// exist now, from this call or an earlier one.
#[cfg(target_os = "linux")]
fn enter_own_namespaces() -> bool {
    static MADE: AtomicBool = AtomicBool::new(false);
    // SAFETY: unshare takes flags only and touches no memory of this process.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWIPC) } == 0
    {
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

/// Whether the filter refuses to start a program. The probe names no file, so nothing starts
/// without the filter either: the kernel then answers that there is no such file.
fn programs_refused() -> bool {
    // SAFETY: execve reads the path, an empty NUL-terminated literal; Linux takes null lists of
    // arguments and environment.
    let started = unsafe { libc::execve(c"".as_ptr(), std::ptr::null(), std::ptr::null()) };
    started == -1 && std::io::Error::last_os_error().raw_os_error() == Some(REFUSED)
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

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
))]
mod seccomp;

/// No filter is written for other architectures: there Landlock alone restricts Linux.
#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
)))]
mod seccomp {
    pub(super) const FILE_LOCKS: u32 = 1;
    pub(super) const SENDMSG: u32 = 2;
    pub(super) const SIGNALS: u32 = 4;
    pub(super) const LAYER: u32 = 8;
    pub(super) const SCOPE: u32 = 16;
    pub(super) const FOLDERS: u32 = 32;

    pub(super) fn names_this_process() -> bool {
        false
    }

    pub(super) fn held() -> Option<u32> {
        None
    }

    pub(super) fn install(_options: u32, _sync: bool, _needed: bool) -> (Option<u32>, bool) {
        (None, false)
    }
}

#[cfg(target_os = "linux")]
mod landlock_layer;

/// What a call observed for `protection` when it reports `outcome`, in words.
pub(crate) fn evidence(protection: Protection, outcome: Outcome) -> Option<&'static str> {
    use {Outcome as O, Protection as P};
    Some(match (protection, outcome) {
        (P::NoCoreDumps, O::Confirmed) => {
            "RLIMIT_CORE reads back 0, and the process is not dumpable"
        }
        (P::NoCoreDumps, O::Refused) => "RLIMIT_CORE or the dumpable flag did not read back",
        (P::NoMemoryReading, O::Confirmed) => "not dumpable, and no thread has a tracer",
        (P::NoMemoryReading, O::Refused) => "the process is dumpable, or a thread has a tracer",
        (P::NoMemoryReading, O::Unknown) => {
            "the threads could not be read, or a PID namespace of its own hides outside tracers"
        }
        (P::NoNewSockets, O::Confirmed) => "the filter answers its mark, and a socket was refused",
        (P::NoNewSockets, O::Refused) => {
            "the socket checks did not confirm the expected restriction"
        }
        (P::NoNewSockets, O::Unknown) => "a socket was refused, but not by this crate's filter",
        (P::NoNewPrograms, O::Confirmed) => "the filter answers its mark, and execve was refused",
        (P::NoNewPrograms, O::Refused) => "execve was not refused",
        (P::NoNewPrograms, O::Unknown) => "execve was refused, but not by this crate's filter",
        (P::EmptyNetwork, O::Confirmed) => {
            "namespace setup recorded, no interface besides loopback listed, no IPv4 routes"
        }
        (P::EmptyNetwork, O::Refused) => {
            "namespace setup or the interface and IPv4 route checks failed"
        }
        (P::NoFileChanges, O::Confirmed) => {
            "the filter answers its mark, and opening for writing was refused"
        }
        (P::NoFileChanges, O::Refused) => {
            "the filter is missing, or opening for writing was not refused"
        }
        (P::SpeculationLimited, O::Confirmed) => {
            "both kinds read back off for good, or the processor is not affected"
        }
        (P::SpeculationLimited, O::Refused) => "a kind did not read back off for good",
        (P::SpeculationLimited, O::Unknown) => {
            "the kernel did not return a state for at least one mechanism"
        }
        (P::WholeProcess, O::Confirmed) => {
            "the process had one thread at the call, or the filter, and the Landlock layer where \
             there is one, reached every thread (TSYNC)"
        }
        (P::WholeProcess, O::Refused) => {
            "the process had other threads, or could not be shown to have one, and the filter or \
             the layer reaches only the calling thread and the threads it starts"
        }
        (P::FileLocksRefused, O::Confirmed) => {
            "the filter has the rule, and a lock on /dev/null was refused"
        }
        (P::FileLocksRefused, O::Refused) => "a lock on /dev/null was not refused",
        (P::FileLocksRefused, O::Unknown) => {
            "a lock was refused without this crate's rule, or the rule could not be probed"
        }
        (P::SendmsgRefused, O::Confirmed) => "the filter has the rule, and sendmsg was refused",
        (P::SendmsgRefused, O::Refused) => "sendmsg was not refused",
        (P::SendmsgRefused, O::Unknown) => {
            "sendmsg was refused without this crate's rule, or the rule could not be probed"
        }
        (P::SignalsToSelfOnly, O::Confirmed) => {
            "the filter answers its mark with the rule, which names this process"
        }
        (P::SignalsToSelfOnly, O::Refused) => {
            "the filter lacks the rule, or the rule names another process"
        }
        (P::SignalsWithinLayer, O::Confirmed) => "the Landlock layer went in with its signal scope",
        (P::SignalsWithinLayer, O::Refused) => {
            "no Landlock layer, or one without the signal scope (before Linux 6.12)"
        }
        (P::FolderWrites, O::Confirmed) => {
            "the Landlock layer took a rule beneath each folder, and the filter lets writes through \
             only in the granted forms"
        }
        (P::FolderWrites, O::Refused) => {
            "a folder was no longer the new, empty one made, Landlock refused its rule or is \
             missing, or an earlier filter or layer keeps every write closed"
        }
        (P::MemoryLocked, O::Confirmed) => "mlockall was accepted in this process",
        (P::MemoryLocked, O::Refused) => "mlockall was refused",
        (P::MemoryLocked, O::Unknown) => {
            "all memory was locked once, here or in the process this one was forked from"
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every answer of PR_GET_SPECULATION_CTRL, by the kernel's spec_ctrl documentation.
    #[test]
    fn a_lock_without_a_mark_is_not_taken_for_this_process() {
        // With a mark: this call's lock, or the mark's word, and nothing else.
        assert_eq!(
            lock_outcome(true, true, Some(true), false),
            Outcome::Confirmed
        );
        assert_eq!(
            lock_outcome(false, false, Some(true), false),
            Outcome::Confirmed
        );
        assert_eq!(
            lock_outcome(true, false, Some(false), false),
            Outcome::Refused
        );
        assert_eq!(
            lock_outcome(false, false, Some(false), false),
            Outcome::NotRequested
        );
        // Without one: this call's own lock is certain, a lock taken before is not.
        assert_eq!(lock_outcome(true, true, None, true), Outcome::Confirmed);
        assert_eq!(lock_outcome(false, false, None, true), Outcome::Unknown);
        assert_eq!(lock_outcome(true, false, None, true), Outcome::Unknown);
        assert_eq!(lock_outcome(true, false, None, false), Outcome::Refused);
        assert_eq!(
            lock_outcome(false, false, None, false),
            Outcome::NotRequested
        );
    }

    #[test]
    fn a_refusal_confirms_only_with_this_crates_filter() {
        assert_eq!(probed(true, true), Outcome::Confirmed);
        assert_eq!(probed(false, true), Outcome::Unknown);
        assert_eq!(probed(true, false), Outcome::Refused);
        // An option: asked or not, the filter's rule or none, the probe refused or not.
        for (asked, rule, refused, outcome) in [
            (true, true, true, Outcome::Confirmed),
            (false, true, true, Outcome::Confirmed),
            (true, false, true, Outcome::Unknown),
            (true, true, false, Outcome::Unknown),
            (true, false, false, Outcome::Refused),
            (false, false, false, Outcome::NotRequested),
        ] {
            assert_eq!(option_probed(asked, rule, refused), outcome);
        }
    }

    #[test]
    fn speculation_answers_are_read_as_the_kernel_defines_them() {
        let (prctl, enable, disable, force, noexec) = (1, 2, 4, 8, 16);
        for (answer, state) in [
            (Some(0), Speculation::Off),
            (Some(prctl | force), Speculation::Off),
            (Some(prctl | disable | force), Speculation::Off),
            (Some(disable), Speculation::Off),
            (Some(prctl | enable), Speculation::On),
            (Some(enable), Speculation::On),
            (Some(prctl | disable), Speculation::On),
            (Some(prctl | noexec), Speculation::On),
            (None, Speculation::Unknown),
        ] {
            assert_eq!(speculation_state(answer), state, "{answer:?}");
        }
    }
}
