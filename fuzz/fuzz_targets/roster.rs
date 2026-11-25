//! The list of thread IDs a Windows worker reads from its parent during its census: a count,
//! then as many IDs, all four bytes little-endian. Zero stands for no observation.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_protection_core::fuzzing;

/// The most threads a census lists, as on Windows.
const MOST: usize = 1 << 16;

fuzz_target!(|bytes: &[u8]| {
    match fuzzing::roster(bytes, MOST) {
        Ok(None) => assert_eq!(bytes.get(..4), Some(&[0; 4][..])),
        Ok(Some(ids)) => {
            assert!(!ids.is_empty() && ids.len() <= MOST);
            assert!(ids[0] > 0 && ids.windows(2).all(|pair| pair[0] < pair[1]));
            let mut again = u32::try_from(ids.len()).unwrap().to_le_bytes().to_vec();
            again.extend(ids.iter().flat_map(|id| id.to_le_bytes()));
            assert!(bytes.starts_with(&again));
        }
        Err(_) => {}
    }
});
