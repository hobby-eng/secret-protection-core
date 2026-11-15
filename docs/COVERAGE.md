# Test coverage

The Linux x86-64 run on 2026-11-15 covered **95.18%** (2,471 of 2,596 measured source lines). All 84 checks passed (33 unit · 20 isolation · 9 secret-memory · 22 worker).

## Measurement

Rust 1.99.1 and cargo-llvm-cov measured revision `3d914c82e0e5921f0c89dbfb4beb842e87662445`. The measured inputs have SHA-256 `5b126b808dbee3fdeaf228fd8b4155f4f5ebff87c64f4a1fe9189b881a645121`. LLVM reported mismatched profile data for 13 functions. The preceding measurement at `a4fd4c5` covered 2,468 of 2,596 lines (95.07%). [Earlier verification record](audits/AUD-015-2026-11-15.md)

## Scope and exclusions

The run covers unit tests inside the crate, the three Linux integration programs and their workers. Continuous profiling records counters for children that lose permission to open files. Integration test sources themselves are outside the denominator. Linux error returns and alternative libc paths account for some uncovered lines. Windows, Apple, Android and WebAssembly code have no Linux line count.

## Reproduce on Linux

From the repository root, in bash, with the pinned toolchain. The workspace laptop runs each Cargo command through `run-capped --`.

```sh
export CARGO_TARGET_DIR="$PWD/target/coverage"
source <(cargo llvm-cov show-env --sh)
export RUSTFLAGS="-C llvm-args=-runtime-counter-relocation"
export LLVM_PROFILE_FILE="$CARGO_TARGET_DIR/spc-%p%c.profraw"
cargo llvm-cov clean --workspace
cargo test --locked --offline
cargo llvm-cov report --summary-only
```

The `%c` in the name of the profile is what counts the processes that isolate themselves: without it each one is refused the writing of its profile when it ends (`LLVM Profile Error: … Permission denied`), and the figure comes out several points lower.

For the source fingerprint, hash each Rust file under `src/` and `tests/`, plus `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml`. Sort by repository-relative path in byte order. Hash the resulting manifest of lowercase SHA-256 digests, two spaces, the path, and a newline per entry.

## Coverage by source file

| File                      | Covered lines | Measured lines | Coverage |
| ------------------------- | ------------: | -------------: | -------: |
| `src/channels.rs`         |            40 |             40 |  100.00% |
| `src/input.rs`            |           137 |            137 |  100.00% |
| `src/os.rs`               |            66 |             66 |  100.00% |
| `src/os/linux.rs`         |           479 |            492 |   97.36% |
| `src/os/linux/seccomp.rs` |           156 |            156 |  100.00% |
| `src/os/unix.rs`          |           491 |            557 |   88.15% |
| `src/os/unix/child.rs`    |            63 |             97 |   64.95% |
| `src/os/unix/forks.rs`    |            17 |             17 |  100.00% |
| `src/protect.rs`          |           414 |            415 |   99.76% |
| `src/protect/closed.rs`   |           131 |            132 |   99.24% |
| `src/protect/options.rs`  |           139 |            139 |  100.00% |
| `src/stack.rs`            |            98 |             98 |  100.00% |
| `src/worker.rs`           |           240 |            250 |   96.00% |
