//! This crate's own secret memory, by address, and the shared mappings of the process that the
//! channel check names: memory that carries data out with no descriptor open.

#[cfg(target_os = "linux")]
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Where this crate's secret memory starts, in slots that a `fork` can copy at any moment, as it
/// cannot a lock another thread holds. A secret past the last slot is not left out: the check
/// names it, which fails closed.
static OWN: [AtomicUsize; 256] = [const { AtomicUsize::new(0) }; 256];

/// The process the slots belong to, by its mark: a child of `fork` inherits them without the
/// secrets, which it does not map, and so has none of its own until it makes one.
static OWNER: crate::os::unix::forks::AtomicMark = crate::os::unix::forks::AtomicMark::new(0);

/// The name the kernel gives memory of `memfd_secret`: a mapping is this crate's only with it
/// and at a remembered start, as a child of `fork` may map other memory where a secret was.
const SECRET_NAME: &str = "/secretmem (deleted)";

#[cfg(target_os = "linux")]
pub(in crate::os) fn remember(start: NonNull<u8>) {
    let start = start.as_ptr() as usize;
    let own = crate::os::unix::forks::mark();
    // The inherited slots are emptied before the owner names this process, so that no check in
    // between takes them for its own; the allocation gate keeps a second writer out.
    if OWNER.load(Ordering::Acquire) != own {
        for slot in &OWN {
            slot.store(0, Ordering::Release);
        }
        OWNER.store(own, Ordering::Release);
    }
    for slot in &OWN {
        if slot
            .compare_exchange(0, start, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

#[cfg(target_os = "linux")]
pub(in crate::os) fn forget(start: NonNull<u8>) {
    let start = start.as_ptr() as usize;
    for slot in &OWN {
        if slot
            .compare_exchange(start, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

/// The shared mappings the process can write, from /proc/self/smaps: those with `sh` and `mw`
/// (may write, after `mprotect` too) among their flags, without this crate's secret memory.
/// `None` when the list cannot be read whole, as when a mapping comes without its flags.
pub(crate) fn shared_mappings() -> Option<Vec<crate::SharedMapping>> {
    let text = std::fs::read_to_string("/proc/self/smaps").ok()?;
    let mut found = Vec::new();
    let mut current: Option<crate::SharedMapping> = None;
    for line in text.lines() {
        if let Some(flags) = line.strip_prefix("VmFlags:") {
            let mapping = current.take()?;
            let flags: Vec<&str> = flags.split_whitespace().collect();
            if flags.contains(&"sh") && flags.contains(&"mw") && !own(&mapping) {
                found.push(mapping);
            }
        } else if let Some(mapping) = header(line)
            && current.replace(mapping).is_some()
        {
            return None;
        }
    }
    current.is_none().then_some(found)
}

fn own(mapping: &crate::SharedMapping) -> bool {
    mapping.name == SECRET_NAME
        && OWNER.load(Ordering::Acquire) == crate::os::unix::forks::mark()
        && OWN
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) == mapping.start)
}

/// A mapping's first line in /proc/self/smaps: "start-end perms offset device inode name".
fn header(line: &str) -> Option<crate::SharedMapping> {
    let mut parts = line.split_whitespace();
    let (start, end) = parts.next()?.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;
    // Past the permissions, offset, device and inode.
    parts.nth(3)?;
    Some(crate::SharedMapping {
        start,
        length: end.checked_sub(start)?,
        name: parts.collect::<Vec<_>>().join(" "),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Key lines are no mapping, and a mapping is read with its name, spaces included.
    #[test]
    fn a_header_is_read_and_a_key_line_is_not() {
        let mapping = header("7f00a000-7f00c000 rw-s 00000000 00:01 42   /tmp/a b (deleted)");
        assert_eq!(
            mapping,
            Some(crate::SharedMapping {
                start: 0x7f00_a000,
                length: 0x2000,
                name: "/tmp/a b (deleted)".to_owned(),
            })
        );
        assert_eq!(header("Size:                  8 kB"), None);
        assert_eq!(header("VmFlags: rd wr sh mr mw me"), None);
    }
}
