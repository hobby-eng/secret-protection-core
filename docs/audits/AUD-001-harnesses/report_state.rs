//! Public Linux API diagnostic. Use a fresh process, without credentials.
use secret_protection_core::{Isolation, Options, Protection, Secret};

fn main() {
    let sample = Secret::zeroed(16);
    let address = sample.as_bytes().as_ptr() as usize;
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let backend = maps
        .lines()
        .find(|line| {
            let Some((range, _)) = line.split_once(' ') else {
                return false;
            };
            let Some((start, end)) = range.split_once('-') else {
                return false;
            };
            let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) else {
                return false;
            };
            (start..end).contains(&address)
        })
        .map(|line| {
            if line.contains("/secretmem") {
                "secretmem"
            } else {
                "fallback"
            }
        });
    println!(
        "sample backend {backend:?}, locked {}, out of children {}",
        sample.is_locked(),
        sample.is_out_of_children()
    );
    drop(sample);
    let first = Isolation::enter_with(Options::new().lock_all_memory());
    let second = Isolation::enter();
    for (label, report) in [("lock requested", first), ("default re-entry", second)] {
        let measure = report
            .measures()
            .into_iter()
            .find(|m| m.protection == Protection::MemoryLocked)
            .unwrap();
        println!("{label}: holds={} proof={}", measure.holds, measure.proof);
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    println!(
        "{}",
        status
            .lines()
            .find(|line| line.starts_with("VmLck:"))
            .unwrap()
    );
}
