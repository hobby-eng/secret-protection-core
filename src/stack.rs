//! [`run_on_protected_stack`]: secret work on a thread whose stack lives in protected pages.
//! [`with_cleared_stack`] and [`clear_stack`]: what secret work left on the calling thread's own
//! stack, overwritten after it.

use std::fmt;
use std::hint::black_box;
use std::io;

use zeroize::Zeroize;

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
    /// The size asked for cannot be a stack.
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
/// and block buffers. Best effort: how deep `work` wrote is not measured, and the thread needs that
/// much free stack. Registers, heap copies and other threads' stacks are left as they are.
#[inline(never)]
pub fn with_cleared_stack<T>(work: impl FnOnce() -> T) -> T {
    let result = run(work);
    clear_stack();
    result
}

/// As [`with_cleared_stack`], with `BYTES` overwritten: for shallow work on a thread that may
/// have less stack to spare.
#[cfg(any(unix, windows))]
#[inline(never)]
pub(crate) fn with_cleared<const BYTES: usize, T>(work: impl FnOnce() -> T) -> T {
    let result = run(work);
    clear::<BYTES>();
    result
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

#[inline(never)]
fn clear<const BYTES: usize>() {
    let mut stack = [0u8; BYTES];
    // Volatile writes; `black_box` keeps the array, and so the writes, where the frames were.
    stack.zeroize();
    black_box(&stack);
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    /// After the clearing the stack below the caller holds none of the work; before it, it does,
    /// which shows that the reading finds what is there.
    #[test]
    fn a_cleared_stack_holds_none_of_the_work() {
        /// "SPC_STK!", which nothing else on the stack holds.
        const MARK: u64 = 0x5350_435f_5354_4b21;
        #[inline(never)]
        fn work() -> u64 {
            let mut words = [MARK; 1024];
            black_box(&mut words);
            words[17]
        }
        assert_eq!(work(), MARK);
        assert!(stack_holds(MARK));
        assert_eq!(with_cleared_stack(work), MARK);
        assert!(!stack_holds(MARK));
    }

    /// Whether the stack below this frame holds `word`, down to twice what is cleared. It is read
    /// through the kernel, since Rust may not read memory that no value was written to.
    #[inline(never)]
    fn stack_holds(word: u64) -> bool {
        use std::os::unix::fs::FileExt;
        let frame = 0u64;
        let end = black_box(&raw const frame) as u64;
        let mut below = vec![0u8; 2 * CLEARED_STACK_BYTES];
        let start = end - below.len() as u64;
        std::fs::File::open("/proc/self/mem")
            .unwrap()
            .read_exact_at(&mut below, start)
            .unwrap();
        let (words, _) = below.as_chunks::<8>();
        words.iter().any(|chunk| u64::from_ne_bytes(*chunk) == word)
    }

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
