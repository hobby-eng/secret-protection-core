//! [`run_on_protected_stack`]: secret work on a thread whose stack lives in protected pages.
//! [`with_cleared_stack`] and [`clear_stack`]: what secret work left on the calling thread's own
//! stack, overwritten after it.

use std::fmt;
use std::io;

/// What protects the pages of a stack.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackProperties {
    /// Locked against swap.
    pub locked: bool,
    /// Left out of core dumps. Never on macOS and iOS, where no call does that for single pages:
    /// there only [`crate::Isolation::no_core_dumps`] keeps a stack out of a dump.
    pub out_of_dumps: bool,
    /// Not given to a child process: it gets zeros, or no pages.
    pub out_of_children: bool,
}

impl StackProperties {
    /// Whether every property that `required` names is there.
    #[cfg(unix)]
    pub(crate) fn covers(self, required: Self) -> bool {
        (self.locked || !required.locked)
            && (self.out_of_dumps || !required.out_of_dumps)
            && (self.out_of_children || !required.out_of_children)
    }
}

/// Why work did not run on a protected stack. It did not start.
#[derive(Debug)]
pub enum StackError {
    /// Windows and WebAssembly give a thread no stack of the program's choosing.
    Unsupported,
    /// The size asked for cannot be rounded up to whole pages. A size the system cannot reserve,
    /// such as one past `isize::MAX`, gives `System` with `OutOfMemory`.
    Size,
    /// The stack lacks a required property; these are the ones it has.
    NotProtected(StackProperties),
    /// The system gave no pages or no thread.
    System(io::Error),
}

impl fmt::Display for StackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("this system offers no protected stack"),
            Self::Size => f.write_str("the stack size asked for is too large"),
            Self::NotProtected(has) => write!(f, "the stack is not protected as required: {has:?}"),
            Self::System(error) => write!(f, "no protected stack: {error}"),
        }
    }
}

impl std::error::Error for StackError {}

/// What [`run_on_protected_stack`] returns: the work's result, and what protected its stack.
#[derive(Debug)]
pub struct StackRun<R> {
    /// What the work returned.
    pub value: R,
    /// What protected the stack while the work ran.
    pub properties: StackProperties,
}

/// Runs `work` on a new thread only when its stack has every property in `required`.
/// After the thread exits the library wipes the supplied stack. With unwinding enabled,
/// a panic propagates to the caller. A panic-abort build exits immediately. Avoid `fork`
/// anywhere in the process while this stack is active. Registers and heap copies have
/// separate lifetimes.
pub fn run_on_protected_stack<R: Send>(
    stack_bytes: usize,
    required: StackProperties,
    work: impl FnOnce() -> R + Send,
) -> Result<StackRun<R>, StackError> {
    crate::os::run_on_stack(stack_bytes, required, work)
        .map(|(value, properties)| StackRun { value, properties })
}

/// How much of the stack below the caller's frame [`clear_stack`] overwrites: a margin over what
/// a secret computation writes there, which nothing measures.
pub const CLEARED_STACK_BYTES: usize = 128 * 1024;

/// Runs `work` in a frame of its own, then overwrites [`CLEARED_STACK_BYTES`] of the calling
/// thread's stack below the caller's frame, where `work` and what it called kept their locals:
/// copies that moves leave behind, and the state of dependencies that never wipe it, such as hash
/// and block buffers; also when `work` panics, as the panic is caught and resumed after the
/// clearing. A foreign exception is caught as `catch_unwind` catches one: the program aborts, or
/// it goes on as a panic. Best effort: how deep `work` wrote is
/// not measured, and the thread needs that much free stack. What `work` captures and returns
/// passes through frames above, which stay as they are, and so do registers, heap copies and
/// other threads' stacks. WebAssembly overwrites nothing (docs/API.md).
#[inline(never)]
pub fn with_cleared_stack<T>(work: impl FnOnce() -> T) -> T {
    with_cleared::<CLEARED_STACK_BYTES, T>(work)
}

/// As [`with_cleared_stack`], with `BYTES` overwritten: for shallow work on a thread that may
/// have less stack to spare. A panic is caught, and raised again once the stack is cleared: the
/// MSVC toolchain runs the drops of an unwinding panic below the frames that panicked, where a
/// clearing would miss them.
#[inline(never)]
pub(crate) fn with_cleared<const BYTES: usize, T>(work: impl FnOnce() -> T) -> T {
    let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| below_cushion(work)));
    clear::<BYTES>();
    done.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// Stack the work's frames keep free below the frame that clears: more than the frames of the
/// clearing take before the cleared bytes start, in an instrumented build too, so that the
/// clearing reaches the top of the work's frames.
const CUSHION_BYTES: usize = 2 << 10;

/// Runs `work` below [`CUSHION_BYTES`] of this frame, never written.
#[inline(never)]
fn below_cushion<T>(work: impl FnOnce() -> T) -> T {
    let cushion = [const { std::mem::MaybeUninit::<u8>::uninit() }; CUSHION_BYTES];
    std::hint::black_box(&cushion);
    run(work)
}

#[inline(never)]
fn run<T>(work: impl FnOnce() -> T) -> T {
    work()
}

/// Overwrites [`CLEARED_STACK_BYTES`] of the calling thread's stack below the caller's frame: on
/// each thread of a pool after secret work it ran, such as the lanes of a password hash.
#[inline(never)]
pub fn clear_stack() {
    clear::<CLEARED_STACK_BYTES>();
}

/// WebAssembly overwrites nothing: the stack lies in linear memory, where the crate cannot tell
/// how much of it is left below the work. rustc puts it first, so a clearing past its start
/// traps; another toolchain may put the program's data there instead.
#[inline(never)]
fn clear<const BYTES: usize>() {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use zeroize::Zeroize;
        // Zeros written once in place into bytes never set before (a slice, as zeroize writes a
        // whole `MaybeUninit` value through a zeroed copy); `black_box` keeps the array, and so
        // the writes, where the frames were.
        let mut stack = [const { std::mem::MaybeUninit::<u8>::uninit() }; BYTES];
        stack.as_mut_slice().zeroize();
        std::hint::black_box(&stack);
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(
    unsafe_code,
    reason = "mach_vm_read_overwrite and ReadProcessMemory are foreign functions"
)]
mod clearing {
    use super::*;
    use std::hint::black_box;

    /// After the clearing the stack below the caller holds none of the work. Work left uncleared
    /// shows that the reading finds what is there; it has a mark of its own, as the clearing
    /// starts below the frames of `with_cleared_stack` and not where that work was. A clearing
    /// first makes the pages read exist: Windows commits a page of a stack when it is first used.
    #[test]
    fn a_cleared_stack_holds_none_of_the_work() {
        /// "SPC_STK!" and "SPC_SEE!", which nothing else on the stack holds.
        const MARK: u64 = 0x5350_435f_5354_4b21;
        const SEEN: u64 = 0x5350_435f_5345_4521;
        clear_stack();
        assert_eq!(work(SEEN), !SEEN);
        assert!(stack_holds(!SEEN));
        assert_eq!(with_cleared_stack(|| work(MARK)), !MARK);
        assert!(!stack_holds(!MARK));
    }

    /// Fills a frame with `mark` and returns its complement, so that only that frame holds it.
    #[inline(never)]
    fn work(mark: u64) -> u64 {
        let mut words = [black_box(mark); 1024];
        black_box(&mut words);
        !words[17]
    }

    /// `clear_stack` alone, as a thread of a pool calls it after the work it ran, clears what that
    /// work left below the caller's frame.
    #[test]
    fn clear_stack_alone_clears_what_the_work_left() {
        const MARK: u64 = 0x5350_435f_504f_4f21; // "SPC_POO!"
        assert_eq!(work(MARK), !MARK);
        clear_stack();
        assert!(!stack_holds(!MARK));
    }

    /// Locals of the closure itself, which an optimized build keeps in the frame that runs it,
    /// are cleared too.
    #[test]
    fn locals_of_the_closure_itself_are_cleared_too() {
        const MARK: u64 = 0x5350_435f_434c_4f21; // "SPC_CLO!"
        let result = with_cleared_stack(|| {
            let mut words = [black_box(MARK); 1024];
            black_box(&mut words);
            !words[5]
        });
        assert_eq!(result, !MARK);
        assert!(!stack_holds(!MARK));
    }

    /// Work that panics leaves the stack cleared all the same, once the panic is caught.
    #[test]
    fn a_panic_unwinding_out_of_the_work_clears_the_stack_too() {
        const MARK: u64 = 0x5350_435f_504e_4321; // "SPC_PNC!"
        #[inline(never)]
        fn failing() -> u64 {
            let mut words = [black_box(MARK); 1024];
            black_box(&mut words);
            std::panic::panic_any(!words[3]);
        }
        let caught = std::panic::catch_unwind(|| with_cleared_stack(failing));
        assert_eq!(caught.unwrap_err().downcast_ref::<u64>(), Some(&!MARK));
        assert!(!stack_holds(!MARK));
    }

    /// Whether the cleared window below this frame holds the word whose complement is given:
    /// what is cleared, less a margin for the frames of the clearing itself, as an instrumented
    /// build makes every frame larger. The word itself is made only after the reading, so that
    /// neither an argument saved on the stack nor a register saved by a callee puts it in the
    /// window. It is read through the system, since Rust may not read memory no value was
    /// written to.
    #[inline(never)]
    fn stack_holds(complement: u64) -> bool {
        let frame = 0u64;
        let end = black_box(&raw const frame) as usize;
        let mut below = vec![0u8; CLEARED_STACK_BYTES - (16 << 10)];
        read_own(end - below.len(), &mut below);
        let word = (!black_box(complement)).to_ne_bytes();
        // At every byte: 32-bit x86 aligns a `u64` to 4 bytes only, so the frames' words need not
        // start where 8-byte steps from the window's start would look.
        below.windows(word.len()).any(|bytes| bytes == word)
    }

    /// Reads `into.len()` bytes of this process's memory from `start`, through the system.
    #[cfg(target_os = "linux")]
    fn read_own(start: usize, into: &mut [u8]) {
        use std::os::unix::fs::FileExt;
        let memory = std::fs::File::open("/proc/self/mem").unwrap();
        memory.read_exact_at(into, start as u64).unwrap();
    }

    #[cfg(target_os = "macos")]
    fn read_own(start: usize, into: &mut [u8]) {
        // The task port of the process, which libc declares only as deprecated.
        unsafe extern "C" {
            static mach_task_self_: libc::mach_port_t;
            fn mach_vm_read_overwrite(
                task: libc::mach_port_t,
                address: u64,
                size: u64,
                data: u64,
                read: *mut u64,
            ) -> libc::kern_return_t;
        }
        let mut read = 0;
        // SAFETY: the call writes at most `into.len()` bytes, into `into`, and the count into
        // `read`; the task port is the process's own, which the C library set up.
        let status = unsafe {
            mach_vm_read_overwrite(
                mach_task_self_,
                start as u64,
                into.len() as u64,
                into.as_mut_ptr() as u64,
                &raw mut read,
            )
        };
        assert_eq!((status, read), (0, into.len() as u64));
    }

    #[cfg(windows)]
    fn read_own(start: usize, into: &mut [u8]) {
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut read = 0;
        // SAFETY: the call writes at most `into.len()` bytes, into `into`, and the count into
        // `read`; the handle is the constant that names the process itself.
        let done = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                start as *const _,
                into.as_mut_ptr().cast(),
                into.len(),
                &raw mut read,
            )
        };
        assert!(
            done != 0 && read == into.len(),
            "{}",
            io::Error::last_os_error()
        );
    }
}

/// The protected stack, which only Linux reads back here.
#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    /// A refused protected stack says which refusal it was.
    #[test]
    fn a_refused_stack_says_why() {
        let texts = [
            StackError::Unsupported.to_string(),
            StackError::Size.to_string(),
            StackError::NotProtected(StackProperties::default()).to_string(),
            StackError::System(io::Error::from_raw_os_error(11)).to_string(),
        ];
        let unique: std::collections::BTreeSet<&String> = texts.iter().collect();
        assert_eq!(unique.len(), texts.len(), "{texts:?}");
    }

    /// The VmFlags of the mapping that holds `address`, and the permissions of the bytes just
    /// below and just above that mapping.
    fn around(address: usize) -> (String, String, String) {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut ranges = Vec::new();
        for line in smaps.lines() {
            if let Some(flags) = line.strip_prefix("VmFlags:") {
                if let Some(last) = ranges.last_mut() {
                    let (_, _, _, own): &mut (usize, usize, String, String) = last;
                    *own = flags.trim().to_owned();
                }
            } else if let Some((range, rest)) = line.split_once(' ')
                && let Some((start, end)) = range.split_once('-')
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                ranges.push((start, end, rest[..4].to_owned(), String::new()));
            }
        }
        let permissions = |at: usize| {
            ranges
                .iter()
                .find(|(start, end, _, _)| (*start..*end).contains(&at))
                .map(|(_, _, permissions, _)| permissions.clone())
                .unwrap_or_default()
        };
        let (start, end, _, flags) = ranges
            .iter()
            .find(|(start, end, _, _)| (*start..*end).contains(&address))
            .unwrap();
        (flags.clone(), permissions(start - 1), permissions(*end))
    }

    #[test]
    fn work_runs_on_a_protected_stack_and_panics_come_back() {
        let none = StackProperties::default();
        let run = run_on_protected_stack(256 << 10, none, || {
            let secret = [0x5a_u8; 64];
            around(std::hint::black_box(&secret).as_ptr() as usize)
        })
        .unwrap();
        let (flags, below, above) = run.value;
        assert!(run.properties.out_of_dumps && run.properties.out_of_children);
        assert!(flags.contains("dd") && flags.contains("wf"), "{flags}");
        assert_eq!(flags.contains("lo"), run.properties.locked, "{flags}");
        assert!(below.starts_with("---") && above.starts_with("---"));
        let panicked = std::panic::catch_unwind(|| {
            let _ = run_on_protected_stack(64 << 10, none, || panic!("work that fails"));
        });
        assert!(panicked.is_err());
    }

    /// A size that cannot be rounded up to whole pages is refused, and the work does not run.
    #[test]
    fn a_size_beyond_every_stack_is_refused() {
        let mut ran = false;
        let refused = run_on_protected_stack(usize::MAX, StackProperties::default(), || ran = true);
        assert!(matches!(refused, Err(StackError::Size)));
        assert!(!ran);
        let all = StackProperties {
            locked: true,
            out_of_dumps: true,
            out_of_children: true,
        };
        assert!(all.covers(StackProperties::default()) && all.covers(all));
        assert!(!StackProperties::default().covers(all));
    }
}
