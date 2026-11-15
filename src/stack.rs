//! [`run_on_protected_stack`]: secret work on a thread whose stack lives in protected pages.

/// What [`run_on_protected_stack`] returns: the work's result, and whether its stack was locked.
#[derive(Debug)]
pub struct StackRun<R> {
    /// What the work returned.
    pub value: R,
    /// Whether the stack's pages were locked against swap (the lock limit allows it).
    pub locked: bool,
}

/// Runs `work` on a new thread whose stack (at least `stack_bytes`) lies in protected pages:
/// locked where the limit allows, out of core dumps and child processes, between guard pages, and
/// wiped after the thread ends, so the work's local variables go with it. A panic in `work` comes
/// back to the caller. Registers, the caller's stack and heap copies are not covered. Fails with
/// `Unsupported` on Windows and in WebAssembly.
pub fn run_on_protected_stack<R: Send>(
    stack_bytes: usize,
    work: impl FnOnce() -> R + Send,
) -> std::io::Result<StackRun<R>> {
    crate::os::run_on_stack(stack_bytes, work).map(|(value, locked)| StackRun { value, locked })
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

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
        let run = run_on_protected_stack(256 << 10, || {
            let secret = [0x5a_u8; 64];
            around(std::hint::black_box(&secret).as_ptr() as usize)
        })
        .unwrap();
        let (flags, below, above) = run.value;
        assert!(flags.contains("dd") && flags.contains("wf"), "{flags}");
        assert_eq!(flags.contains("lo"), run.locked, "{flags}");
        assert!(below.starts_with("---") && above.starts_with("---"));
        let panicked = std::panic::catch_unwind(|| {
            let _ = run_on_protected_stack(64 << 10, || panic!("work that fails"));
        });
        assert!(panicked.is_err());
    }
}
