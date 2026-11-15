//! Where the pages of a secret and of a work area lie, as the system reports them. The program has a
//! `main` of its own (`harness = false`), so that the counting allocator sees no allocation of
//! another thread; a process under a low lock limit, which may end by a signal, is a child process
//! that it starts again in a role.
#![allow(
    unsafe_code,
    reason = "a global allocator, and the system calls that tell where pages lie and set the lock \
              limit"
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

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use secret_protection_core::Secret;
#[cfg(not(target_arch = "wasm32"))]
use secret_protection_core::WorkArea;

/// The system's allocator, counting the allocations it makes.
struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call goes to the system's allocator unchanged; reallocation and zeroed allocation
// go through `alloc`, so they are counted too.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller keeps the contract of `GlobalAlloc::alloc`, which `System` needs.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as for `alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// AddressSanitizer asks the program for its options. Its leak check needs ptrace, which an
/// isolated process refuses, and a worker gets no environment to turn it off in.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn __asan_default_options() -> *const std::ffi::c_char {
    c"detect_leaks=0".as_ptr()
}

fn main() {
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
}

/// Runs one check unless a `--skip <part of its name>` argument leaves it out, as the standard
/// harness does. A sanitizer puts its own `mlock` in, which locks nothing, so the checks of
/// locked memory have to be left out under it.
fn run(name: &str, check: fn()) {
    let arguments: Vec<String> = std::env::args().collect();
    let skipped = arguments
        .windows(2)
        .any(|pair| pair[0] == "--skip" && name.contains(pair[1].as_str()));
    if skipped {
        return println!("test {name} ... ignored");
    }
    check();
    println!("test {name} ... ok");
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
fn lock_limit() -> u64 {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct, which lives for the call.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
    assert_eq!(read, 0);
    limit.rlim_cur
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
        let address = secret.as_bytes().as_ptr() as usize;
        let mappings = mappings();
        let mapping = mappings
            .iter()
            .find(|mapping| mapping.range.contains(&address))
            .unwrap();
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
        let address = secret.as_bytes().as_ptr() as usize;
        let mappings = mappings();
        let mapping = mappings
            .iter()
            .find(|mapping| mapping.range.contains(&address))
            .unwrap();
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
        assert!(status.success(), "{role}: {status}");
    }

    /// The name of the mapping a secret lies in: `/secretmem` for secret memory.
    fn mapping_name(secret: &Secret) -> String {
        let address = secret.as_bytes().as_ptr() as usize;
        let mappings = mappings();
        let mapping = mappings
            .iter()
            .find(|mapping| mapping.range.contains(&address))
            .unwrap();
        mapping.name.clone()
    }

    /// The `late` role. A `fork` that another thread has begun runs no handler registered after
    /// it started, so a process that already has threads cannot keep `fork` out any more: its
    /// secrets lie on locked anonymous pages, never in secret memory, and stay there once it is
    /// alone again.
    pub(super) fn first_secret_among_threads() {
        let other = std::thread::spawn(std::thread::park);
        let first = Secret::with_capacity(16);
        assert!(!mapping_name(&first).starts_with("/secretmem"));
        // Anonymous pages: out of core dumps, and zeros in a child.
        assert!(first.is_out_of_dumps() && first.is_out_of_children());
        other.thread().unpark();
        other.join().unwrap();
        let later = Secret::with_capacity(16);
        assert!(!mapping_name(&later).starts_with("/secretmem"));
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
                if child == 0 {
                    libc::_exit(0);
                }
                let mut status = 0;
                libc::waitpid(child, &mut status, 0);
                status
            }
        });
        while !WAITING.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let secret = Secret::with_capacity(16);
        assert!(!mapping_name(&secret).starts_with("/secretmem"));
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
            eprintln!("This kernel gives no secret memory: the race with fork is not checked.");
            return;
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
            if child == 0 {
                let found = holds_secret_memory();
                // SAFETY: ends the child at once.
                unsafe { libc::_exit(i32::from(found)) };
            }
            let mut status = 0;
            // SAFETY: waits for the child just made and writes its status.
            assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
            inherited += i32::from(status != 0);
        }
        DONE.store(true, Ordering::Relaxed);
        let made = maker.join().unwrap();
        assert!(made > 1000, "only {made} secrets were made meanwhile");
        assert_eq!(
            inherited, 0,
            "children inherited a descriptor of secret memory"
        );
    }

    /// Whether one of the descriptors 3 to 63 names secret memory, as the link in /proc/self/fd
    /// says, without any allocation.
    fn holds_secret_memory() -> bool {
        (3..64_u8).any(|descriptor| {
            let mut path = *b"/proc/self/fd/\0\0\0";
            if descriptor < 10 {
                path[14] = b'0' + descriptor;
            } else {
                path[14] = b'0' + descriptor / 10;
                path[15] = b'0' + descriptor % 10;
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
        let status = Command::new(std::env::current_exe().unwrap())
            .env(ROLE, "child")
            .status()
            .unwrap();
        assert!(status.success(), "{status}");
    }

    /// Child process: a two-page secret is written and read under every lock limit down to 0, and must
    /// be locked exactly when the limit allows. Needs a process without CAP_IPC_LOCK.
    pub(super) fn secrets_under_every_lock_limit() {
        // SAFETY: sysconf takes an integer and touches no memory of this process.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let public = vec![0x5a; page as usize + 1];
        let highest = super::lock_limit().min(HIGHEST_LOCK_LIMIT);
        for pages in (0..=highest / page).rev() {
            let limit = libc::rlimit {
                rlim_cur: pages * page,
                rlim_max: pages * page,
            };
            // SAFETY: setrlimit reads the struct, which lives for the call.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) }, 0);
            let mut secret = Secret::with_capacity(public.len());
            secret.push(&public).unwrap();
            assert_eq!(secret.as_bytes(), public, "{pages} pages");
            let holds = limit.rlim_cur >= public.len() as u64;
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
            "Other programs hold this user's lock limit: the partly used quota is not checked."
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
