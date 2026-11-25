//! Where the pages of a secret and of a work area lie, as the system reports them. The program has a
//! `main` of its own (`harness = false`): a process under a low lock limit, which may end by a
//! signal, is a child process that it starts again in a role.
#![allow(
    unsafe_code,
    reason = "the system calls that tell where pages lie and set the lock limit"
)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a test program with a main of its own reports each check, as a test harness does"
)]
#![allow(
    clippy::unwrap_used,
    reason = "a test program with a main of its own, which clippy does not see as a test: a failed \
              check ends it, as in a test harness"
)]

#[path = "support/run.rs"]
mod support;
use support::run;

use secret_protection_core::Secret;
#[cfg(not(target_arch = "wasm32"))]
use secret_protection_core::WorkArea;

/// AddressSanitizer asks the program for its options. Its leak check needs ptrace, which an
/// isolated process refuses, and a worker gets no environment to turn it off in.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn __asan_default_options() -> *const std::ffi::c_char {
    c"detect_leaks=0".as_ptr()
}

fn main() {
    // A secret of a quarter of the address space, which no system gives.
    #[cfg(unix)]
    if std::env::var(NO_MEMORY).is_ok() {
        drop(Secret::with_capacity(usize::MAX / 4));
        return;
    }
    #[cfg(target_os = "linux")]
    match std::env::var(linux::ROLE).as_deref() {
        Ok("child") => return linux::secrets_under_every_lock_limit(),
        Ok("forks") => return linux::secrets_made_during_forks(),
        Ok("late") => return linux::first_secret_among_threads(),
        Ok("gated") => return linux::a_secret_under_a_fork_handlers_lock(),
        _ => {}
    }
    // WebAssembly has no pages of its own to give a secret: it is a heap buffer there.
    #[cfg(any(target_os = "linux", windows))]
    run(
        "a secret lies on pages kept out of swap and core dumps",
        a_secret_lies_on_pages_kept_out_of_swap_and_core_dumps,
    );
    #[cfg(target_os = "linux")]
    run(
        "a secret works under every lock limit and says whether it is locked",
        linux::a_secret_works_under_every_lock_limit,
    );
    #[cfg(target_os = "linux")]
    run(
        "no forked child inherits a descriptor of secret memory",
        linux::no_forked_child_inherits_secret_memory,
    );
    #[cfg(target_os = "linux")]
    run(
        "a process that had threads before its first secret takes no secret memory",
        || linux::role_ends_well("late"),
    );
    #[cfg(target_os = "linux")]
    run(
        "a secret made under a lock that a fork handler waits for does not hang",
        || linux::role_ends_well("gated"),
    );
    #[cfg(not(target_arch = "wasm32"))]
    run(
        "the work area lies on pages of its own, locked where the limit allows",
        the_work_area_lies_on_pages_of_its_own,
    );
    run(
        "six hundred secrets made one after another each report their core-dump exclusion",
        six_hundred_secrets_made_one_after_another_report_their_core_dump_exclusion,
    );
    #[cfg(unix)]
    run(
        "a child of fork leaves the buffers of its parent alone and uses its own",
        a_child_of_fork_leaves_the_buffers_of_its_parent_alone,
    );
    #[cfg(unix)]
    run(
        "a secret beyond what the system gives ends the program as a full heap does",
        a_secret_beyond_the_system_ends_the_program,
    );
}

/// The variable that starts this program again to ask for a secret no system gives.
#[cfg(unix)]
const NO_MEMORY: &str = "SECRET_PROTECTION_CORE_TEST_NO_MEMORY";

/// `Secret::with_capacity` ends the program when the system gives no pages, as a `Vec` does when
/// the heap is full: the program does not go on without the secret it asked for.
#[cfg(unix)]
fn a_secret_beyond_the_system_ends_the_program() {
    use std::os::unix::process::ExitStatusExt;
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .env(NO_MEMORY, "1")
        .output()
        .unwrap();
    assert_eq!(output.status.signal(), Some(libc::SIGABRT), "{output:?}");
}

/// A child of `fork` that goes on holds owners of its parent's buffers, whose pages are gone or
/// zeros without a lock there. It drops them without touching the pages, they report nothing,
/// and reaching their bytes ends it; a buffer it makes itself works. The parent's are unharmed.
#[cfg(unix)]
fn a_child_of_fork_leaves_the_buffers_of_its_parent_alone() {
    use secret_protection_core::ClosedSecret;
    let mut secret = Some(Secret::with_capacity(32));
    if let Some(secret) = secret.as_mut() {
        secret.push(b"the parent's").unwrap();
    }
    let mut area = Some(WorkArea::new(8192).unwrap());
    let mut closed = Some(ClosedSecret::with_capacity(16));
    assert!(closed.as_ref().is_some_and(ClosedSecret::is_closed));
    let status = in_child(|| {
        let reports = secret.as_ref().is_some_and(|secret| {
            !secret.is_locked() && !secret.is_out_of_dumps() && !secret.is_out_of_children()
        }) && area.as_ref().is_some_and(|area| {
            !area.is_locked() && !area.is_out_of_dumps() && !area.is_out_of_children()
        }) && closed
            .as_ref()
            .is_some_and(|closed| !closed.is_locked() && !closed.is_closed());
        drop((secret.take(), area.take(), closed.take()));
        let mut own = Secret::with_capacity(8);
        let works = own.push(b"own").is_ok() && own.as_bytes() == b"own";
        reports && works
    });
    assert_eq!(status, Ending::Exit(0));
    // Fork inside the callback, then return normally on both sides. The child never
    // dereferences a pre-fork borrow. Its scope guard belongs to the old generation.
    let mut live = ClosedSecret::with_capacity(8);
    live.push(b"public").unwrap();
    let child = live.read(|_| {
        // SAFETY: this test process is single-threaded at the fork.
        unsafe { libc::fork() }
    });
    assert!(child >= 0);
    if child == 0 {
        let closed = live.is_closed();
        drop(live);
        // SAFETY: finish the child without running the parent's exit handlers.
        unsafe { libc::_exit(i32::from(closed)) };
    }
    let mut status = -1;
    // SAFETY: child is the positive PID returned by this fork.
    let waited = unsafe { libc::waitpid(child, &mut status, 0) };
    assert_eq!(waited, child);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    assert!(live.is_closed());
    assert_eq!(live.read(|b| b.to_vec()), b"public");
    let status = in_child(|| {
        secret
            .as_ref()
            .is_some_and(|secret| secret.as_bytes().is_empty())
    });
    assert_eq!(status, Ending::Signal(libc::SIGABRT));
    assert_eq!(secret.unwrap().as_bytes(), b"the parent's");
}

/// How a child ended.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum Ending {
    Exit(i32),
    Signal(i32),
}

/// Runs `check` in a child of `fork`, which ends with 0 when it holds and 1 when not, and waits
/// for exactly that child. Only from one thread: the child of a process with threads may make
/// only the calls of a signal handler.
#[cfg(unix)]
fn in_child(check: impl FnOnce() -> bool) -> Ending {
    // SAFETY: the child runs `check` and ends at once without returning.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        let held = check();
        // SAFETY: ends the child without running the parent's exit handlers.
        unsafe { libc::_exit(i32::from(!held)) };
    }
    let mut status = 0;
    // SAFETY: waits for the child just made and writes its status.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    if libc::WIFEXITED(status) {
        Ending::Exit(libc::WEXITSTATUS(status))
    } else {
        Ending::Signal(libc::WTERMSIG(status))
    }
}

/// What the system reports of the pages; the unit tests check what `Secret` reports itself.
#[cfg(any(target_os = "linux", windows))]
fn a_secret_lies_on_pages_kept_out_of_swap_and_core_dumps() {
    let mut secret = Secret::with_capacity(16);
    secret.push(b"public").unwrap();
    #[cfg(target_os = "linux")]
    linux::secret_pages_are_marked(&secret);
    #[cfg(windows)]
    assert!(windows::locked(secret.as_bytes().as_ptr()));
    // A closed secret keeps its pages locked while they refuse every access.
    #[cfg(windows)]
    {
        let mut closed = secret_protection_core::ClosedSecret::locked(16).unwrap();
        closed.push(b"public").unwrap();
        let address = closed.read(<[u8]>::as_ptr);
        assert!(closed.is_closed() && closed.is_locked());
        assert!(
            windows::locked(address),
            "the pages of a closed secret left the working set"
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn the_work_area_lies_on_pages_of_its_own() {
    /// One page more than 1 MiB: a size that no other mapping of this program has.
    const AREA_KIB: u32 = 1028;
    #[cfg(target_os = "linux")]
    let before = linux::mappings();
    let area = WorkArea::new(AREA_KIB as usize * 1024).unwrap();
    // Unix locks the area when RLIMIT_MEMLOCK holds all of it; Windows once the working set grew
    // by its size, which the process of a user may ask for.
    #[cfg(unix)]
    let lockable = lock_limit() >= u64::from(AREA_KIB) * 1024;
    #[cfg(not(unix))]
    let lockable = true;
    assert_eq!(area.is_locked(), lockable);
    #[cfg(target_os = "linux")]
    linux::work_area_is_marked(&before, AREA_KIB as usize * 1024, area.is_locked());
}

fn six_hundred_secrets_made_one_after_another_report_their_core_dump_exclusion() {
    // More than the 512 error-report exclusions that Windows holds for a process: each secret
    // gives its own back.
    let out_of_dumps = cfg!(any(target_os = "linux", target_os = "android", windows));
    for _ in 0..600 {
        assert_eq!(Secret::with_capacity(1).is_out_of_dumps(), out_of_dumps);
    }
}

/// RLIMIT_MEMLOCK, the most memory this process may lock.
#[cfg(unix)]
#[allow(
    clippy::useless_conversion,
    reason = "rlim_t is u64 on 64-bit systems and u32 on 32-bit ARM"
)]
fn lock_limit() -> u64 {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct, which lives for the call.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
    assert_eq!(read, 0);
    u64::from(limit.rlim_cur)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ops::Range;
    use std::process::Command;

    use secret_protection_core::{ClosedSecret, Secret, SecretError, WorkArea};

    /// The variable that starts this program as the child of the lock-limit test.
    pub(super) const ROLE: &str = "SECRET_PROTECTION_CORE_TEST_LOCK_LIMITS";

    /// The highest lock limit tried, Linux's default: a higher one, or none, only makes the way
    /// down longer.
    const HIGHEST_LOCK_LIMIT: u64 = 8 << 20;

    /// One mapping of /proc/self/smaps: its addresses, its name and its VmFlags.
    pub(super) struct Mapping {
        range: Range<usize>,
        name: String,
        flags: Vec<String>,
    }

    impl Mapping {
        fn has(&self, flag: &str) -> bool {
            self.flags.iter().any(|own| own == flag)
        }
    }

    pub(super) fn mappings() -> Vec<Mapping> {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut mappings: Vec<Mapping> = Vec::new();
        for line in smaps.lines() {
            if let Some(flags) = line.strip_prefix("VmFlags:") {
                let mapping = mappings.last_mut().unwrap();
                mapping.flags = flags.split_whitespace().map(str::to_owned).collect();
                continue;
            }
            let mut fields = line.split_whitespace();
            let range = fields.next().and_then(|range| range.split_once('-'));
            let Some((Ok(start), Ok(end))) = range.map(|(start, end)| {
                (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            }) else {
                continue;
            };
            // After the range: permissions, offset, device and inode, then the name, which may
            // hold a space.
            let name = fields.skip(4).collect::<Vec<_>>().join(" ");
            mappings.push(Mapping {
                range: start..end,
                name,
                flags: Vec::new(),
            });
        }
        mappings
    }

    /// Out of core dumps (`dd`) on pages of either kind. Anonymous pages are locked (`lo`) and give
    /// a child process zeros (`wf`). Secret memory is shared, so a child gets none of it (`dc`),
    /// and its kind is what keeps it out of swap: since Linux commit 97d34aa65c29 its folios are
    /// unevictable and the mapping has no `lo`, which an older kernel's has.
    pub(super) fn secret_pages_are_marked(secret: &Secret) {
        let mapping = mapping_of(secret);
        let flags: &[&str] = if mapping.name.starts_with("/secretmem") {
            &["dd", "dc"]
        } else {
            &["dd", "lo", "wf"]
        };
        assert!(
            flags.iter().all(|flag| mapping.has(flag)),
            "{} {:?}",
            mapping.name,
            mapping.flags
        );
    }

    /// The pages of `secret` are kept out of swap: secret memory, or anonymous pages marked
    /// locked (`lo`).
    pub(super) fn is_out_of_swap(secret: &Secret) {
        let mapping = mapping_of(secret);
        assert!(
            mapping.name.starts_with("/secretmem") || mapping.has("lo"),
            "{} {:?}",
            mapping.name,
            mapping.flags
        );
    }

    /// The one new mapping of `bytes` bytes is out of core dumps and gives a child zeros, and it
    /// is locked exactly when the area says so.
    pub(super) fn work_area_is_marked(before: &[Mapping], bytes: usize, locked: bool) {
        let mappings = mappings();
        let new: Vec<&Mapping> = mappings
            .iter()
            .filter(|mapping| mapping.range.len() == bytes)
            .filter(|mapping| before.iter().all(|old| old.range != mapping.range))
            .collect();
        assert_eq!(new.len(), 1);
        let area = new[0];
        assert!(area.has("dd") && area.has("wf"), "{:?}", area.flags);
        assert_eq!(area.has("lo"), locked, "{:?}", area.flags);
        // It keeps the huge pages the system gives: only a secret refuses them.
        assert!(!area.has("nh"), "{:?}", area.flags);
    }

    /// With no memory to lock, work that requires a locked stack does not run, and work that
    /// requires nothing runs on a stack that says it is not locked.
    fn a_stack_that_must_be_locked_is_refused() {
        use secret_protection_core::{StackError, StackProperties, run_on_protected_stack};
        let locked = StackProperties {
            locked: true,
            ..StackProperties::default()
        };
        let mut ran = false;
        let refused = run_on_protected_stack(64 << 10, locked, || ran = true);
        assert!(
            matches!(refused, Err(StackError::NotProtected(has)) if !has.locked && has.out_of_dumps),
            "{refused:?}"
        );
        assert!(!ran);
        let run = run_on_protected_stack(64 << 10, StackProperties::default(), || 7).unwrap();
        assert_eq!((run.value, run.properties.locked), (7, false));
    }

    /// In a child process, which forks: the test itself keeps to one thread.
    pub(super) fn no_forked_child_inherits_secret_memory() {
        role_ends_well("forks");
    }

    /// Starts this program again in `role` and expects it to end well, within a minute: a role
    /// that hangs is ended.
    pub(super) fn role_ends_well(role: &str) {
        let mut process = Command::new(std::env::current_exe().unwrap())
            .env(ROLE, role)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let status = loop {
            if let Some(status) = process.try_wait().unwrap() {
                break status;
            }
            let late = std::time::Instant::now() >= deadline;
            if late {
                process.kill().unwrap();
            }
            assert!(!late, "{role}: not done within a minute");
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        // The messages of a role are a few lines, which the pipe holds until it is read.
        let mut said = Vec::new();
        std::io::Read::read_to_end(&mut process.stderr.take().unwrap(), &mut said).unwrap();
        crate::support::role_ended(role, status, &said);
    }

    /// The mapping a secret lies in; its name is `/secretmem` for secret memory.
    fn mapping_of(secret: &Secret) -> Mapping {
        let address = secret.as_bytes().as_ptr() as usize;
        let mut mappings = mappings();
        let place = mappings
            .iter()
            .position(|mapping| mapping.range.contains(&address))
            .unwrap();
        mappings.swap_remove(place)
    }

    /// Whether this kernel joins small pages into huge ones at all.
    fn has_huge_pages() -> bool {
        std::path::Path::new("/sys/kernel/mm/transparent_hugepage/enabled").exists()
    }

    /// Checks the anonymous fallback when another thread exists at the first allocation,
    /// including its dump, fork and page-size properties.
    pub(super) fn first_secret_among_threads() {
        let other = std::thread::spawn(std::thread::park);
        let first = Secret::with_capacity(16);
        assert!(!mapping_of(&first).name.starts_with("/secretmem"));
        // Anonymous pages: out of core dumps, and zeros in a child.
        assert!(first.is_out_of_dumps() && first.is_out_of_children());
        // Small pages only (`nh`): joining them into a huge one would copy the secret.
        assert!(!has_huge_pages() || mapping_of(&first).has("nh"));
        other.thread().unpark();
        other.join().unwrap();
        let later = Secret::with_capacity(16);
        assert!(!mapping_of(&later).name.starts_with("/secretmem"));
    }

    /// The `gated` role. The program has a fork handler of its own that waits for a lock. A
    /// thread forks: the fork takes the gate of secret memory, then waits in that handler. The
    /// thread that holds the lock makes a secret meanwhile. It must not wait for the gate for
    /// ever: it takes anonymous pages, and the fork goes on once the lock is free.
    pub(super) fn a_secret_under_a_fork_handlers_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static LOCKED: AtomicBool = AtomicBool::new(false);
        static WAITING: AtomicBool = AtomicBool::new(false);
        unsafe extern "C" fn wait_for_the_lock() {
            WAITING.store(true, Ordering::Release);
            while LOCKED.load(Ordering::Acquire) {
                // SAFETY: sched_yield takes nothing and touches no memory.
                unsafe { libc::sched_yield() };
            }
        }
        unsafe extern "C" {
            fn pthread_atfork(
                prepare: Option<unsafe extern "C" fn()>,
                parent: Option<unsafe extern "C" fn()>,
                child: Option<unsafe extern "C" fn()>,
            ) -> libc::c_int;
        }
        // SAFETY: registers a function that lives as long as the program.
        let registered = unsafe { pthread_atfork(Some(wait_for_the_lock), None, None) };
        assert_eq!(registered, 0);
        // The first secret, made alone: from now on a fork takes the gate, and takes it before
        // it runs the handler above, which was registered earlier.
        drop(Secret::with_capacity(16));
        LOCKED.store(true, Ordering::Release);
        let forking = std::thread::spawn(|| {
            // SAFETY: the child ends at once; the parent waits for it and reads its status.
            unsafe {
                let child = libc::fork();
                assert!(child >= 0, "fork failed");
                if child == 0 {
                    libc::_exit(0);
                }
                let mut status = -1;
                assert_eq!(libc::waitpid(child, &mut status, 0), child);
                status
            }
        });
        while !WAITING.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let secret = Secret::with_capacity(16);
        assert!(!mapping_of(&secret).name.starts_with("/secretmem"));
        LOCKED.store(false, Ordering::Release);
        assert_eq!(forking.join().unwrap(), 0);
    }

    /// The `forks` role: one thread makes and drops secrets, each of which holds a descriptor of
    /// secret memory open for a moment, while this thread forks two thousand times. No child may
    /// find such a descriptor among those it inherited: it could map the pages of a later secret.
    pub(super) fn secrets_made_during_forks() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static DONE: AtomicBool = AtomicBool::new(false);
        let sample = Secret::with_capacity(1);
        let address = sample.as_bytes().as_ptr() as usize;
        let secret_memory = mappings().iter().any(|mapping| {
            mapping.range.contains(&address) && mapping.name.starts_with("/secretmem")
        });
        drop(sample);
        if !secret_memory {
            crate::support::skip_role(
                "This kernel gives no secret memory: the race with fork is not checked.",
            );
        }
        let maker = std::thread::spawn(|| {
            let mut made = 0_u64;
            while !DONE.load(Ordering::Relaxed) {
                drop(Secret::with_capacity(64));
                made += 1;
            }
            made
        });
        let mut inherited = 0;
        for _ in 0..2000 {
            // SAFETY: the child makes only calls that a signal handler may make.
            let child = unsafe { libc::fork() };
            assert!(child >= 0, "fork failed");
            if child == 0 {
                let found = holds_secret_memory();
                // SAFETY: ends the child at once.
                unsafe { libc::_exit(i32::from(found)) };
            }
            let mut status = -1;
            // SAFETY: waits for the child just made and writes its status.
            assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
            assert!(libc::WIFEXITED(status), "a child ended by a signal");
            inherited += i32::from(libc::WEXITSTATUS(status) != 0);
        }
        DONE.store(true, Ordering::Relaxed);
        let made = maker.join().unwrap();
        assert!(made > 1000, "only {made} secrets were made meanwhile");
        assert_eq!(
            inherited, 0,
            "children inherited a descriptor of secret memory"
        );
    }

    /// Whether one of the descriptors 3 to 255 names secret memory, as the link in /proc/self/fd
    /// says, without any allocation.
    fn holds_secret_memory() -> bool {
        (3..=255_u8).any(|descriptor| {
            // Up to three digits, and the NUL after them.
            let mut path = *b"/proc/self/fd/\0\0\0\0";
            let digits = [descriptor / 100, descriptor / 10 % 10, descriptor % 10];
            let first = match descriptor {
                0..10 => 2,
                10..100 => 1,
                _ => 0,
            };
            for (slot, digit) in path[14..].iter_mut().zip(&digits[first..]) {
                *slot = b'0' + digit;
            }
            let mut target = [0_u8; 64];
            // SAFETY: readlink reads the NUL-terminated path and writes at most the buffer's
            // length into it.
            let length = unsafe {
                libc::readlink(
                    path.as_ptr().cast(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            usize::try_from(length).is_ok_and(|length| target[..length].starts_with(b"/secretmem"))
        })
    }

    /// In a child process: the limit stays its own, and so does a SIGBUS at a write to a page
    /// beyond the limit.
    pub(super) fn a_secret_works_under_every_lock_limit() {
        let output = Command::new(std::env::current_exe().unwrap())
            .env(ROLE, "child")
            .output()
            .unwrap();
        crate::support::role_ended("child", output.status, &output.stderr);
    }

    /// Exercises a two-page secret at page-aligned limits from the smaller of the test cap
    /// and the process limit down to zero. Requires a process without CAP_IPC_LOCK.
    #[allow(
        clippy::useless_conversion,
        reason = "rlim_t is u64 on 64-bit systems and u32 on 32-bit ARM"
    )]
    pub(super) fn secrets_under_every_lock_limit() {
        // SAFETY: sysconf takes an integer and touches no memory of this process.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let public = vec![0x5a; page as usize + 1];
        let highest = super::lock_limit().min(HIGHEST_LOCK_LIMIT);
        for pages in (0..=highest / page).rev() {
            let limit = libc::rlimit {
                rlim_cur: (pages * page).try_into().unwrap(),
                rlim_max: (pages * page).try_into().unwrap(),
            };
            // SAFETY: setrlimit reads the struct, which lives for the call.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) }, 0);
            let mut secret = Secret::with_capacity(public.len());
            secret.push(&public).unwrap();
            assert_eq!(secret.as_bytes(), public, "{pages} pages");
            let holds = u64::from(limit.rlim_cur) >= public.len() as u64;
            assert_eq!(secret.is_locked(), holds, "{pages} pages");
            drop(secret);
            // The strict constructors refuse what the limit does not hold, before any byte.
            assert_eq!(
                Secret::locked(public.len()).err(),
                (!holds).then_some(SecretError::NotLocked),
                "{pages} pages"
            );
            assert_eq!(
                ClosedSecret::locked(public.len()).is_ok(),
                holds,
                "{pages} pages"
            );
            if pages == 0 {
                assert_eq!(WorkArea::locked(1).err(), Some(SecretError::NotLocked));
                a_stack_that_must_be_locked_is_refused();
            }
            if pages == 4 {
                super::quota_partly_used(page as usize);
            }
        }
        a_stack_without_a_thread_is_an_error();
    }

    /// When the system gives no thread, the work does not run and the call says why. Needs a
    /// process without CAP_SYS_RESOURCE, which the limit does not hold back.
    fn a_stack_without_a_thread_is_an_error() {
        use secret_protection_core::{StackError, StackProperties, run_on_protected_stack};
        // One process or thread for this user, who has that many already.
        let limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: setrlimit reads the struct, which lives for the call.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limit) }, 0);
        let mut ran = false;
        let refused = run_on_protected_stack(64 << 10, StackProperties::default(), || ran = true);
        assert!(
            matches!(&refused, Err(StackError::System(error)) if error.raw_os_error() == Some(libc::EAGAIN)),
            "{refused:?}"
        );
        assert!(!ran);
    }
}

/// With three of four lockable pages already taken, every secret the strict constructor still gives
/// must really be locked, and at least one request must be refused. Secret memory and `mlock` are
/// counted separately, so which requests fail depends on the kernel.
#[cfg(target_os = "linux")]
fn quota_partly_used(page: usize) {
    use secret_protection_core::{Secret, SecretError};
    let Ok(held) = Secret::locked(3 * page) else {
        eprintln!(
            "{}other programs hold this user's lock limit: the partly used quota is not checked.",
            crate::support::NOT_CHECKED
        );
        return;
    };
    let (mut given, mut refused) = (Vec::new(), 0);
    for pages in 1..=4 {
        match Secret::locked(pages * page) {
            Ok(secret) => {
                linux::is_out_of_swap(&secret);
                given.push(secret);
            }
            Err(error) => {
                assert_eq!(error, SecretError::NotLocked);
                refused += 1;
            }
        }
    }
    assert!(refused > 0);
    drop((held, given));
}

#[cfg(windows)]
mod windows {
    use std::mem::size_of;

    use windows_sys::Win32::System::ProcessStatus::{
        K32QueryWorkingSetEx, PSAPI_WORKING_SET_EX_INFORMATION,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    /// Valid (bit 0) and Locked (bit 22) of PSAPI_WORKING_SET_EX_BLOCK.
    const VALID_AND_LOCKED: usize = 1 | 1 << 22;

    /// Whether the page that holds `address` lies in the working set, locked there.
    pub(super) fn locked(address: *const u8) -> bool {
        let mut page = PSAPI_WORKING_SET_EX_INFORMATION {
            VirtualAddress: address.cast_mut().cast(),
            ..Default::default()
        };
        // SAFETY: the query fills the attributes of the one page that `page` names; the pseudo
        // handle of this process needs no closing.
        let read = unsafe {
            K32QueryWorkingSetEx(
                GetCurrentProcess(),
                (&raw mut page).cast(),
                size_of::<PSAPI_WORKING_SET_EX_INFORMATION>() as u32,
            )
        } != 0;
        // SAFETY: the attributes are one word, which the query wrote.
        read && unsafe { page.VirtualAttributes.Flags } & VALID_AND_LOCKED == VALID_AND_LOCKED
    }
}
