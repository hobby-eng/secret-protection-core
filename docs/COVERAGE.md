# Test coverage

On 2026-11-15 UTC the tests covered **97.41%** of the source lines that LLVM reports for the Linux x86-64 build (2,217 of 2,276). The run passed 29 unit tests and 47 checks of the three test programs `isolation`, `secret_memory` and `worker`, the worker's own side included; none was skipped.

## Measurement

Rust 1.99.1 and cargo-llvm-cov 0.9.1 measured the Linux build on kernel 7.0.0-43-generic, x86-64. The measured source is the working tree that follows commit `c0c472af2327cc55a561881201db9830613bd3fc`; the SHA-256 fingerprint of its inputs is `db750b5041779ce841332935b6fbbb5067be931c62b5dbeda41ba67fb31a5808`.

The tests start child processes that isolate themselves and can then write no file, so a profile written when a process ends would be lost. The counters are therefore synced to the profile file as they change (`%c` in its name, with LLVM's `-runtime-counter-relocation`), and such a child is counted.

A worker is counted as well: a build for the measurement (`--cfg coverage`, which cargo-llvm-cov sets) gives it the name of the profile, the one variable of its parent's beside its setting. An ordinary build gives it none.

What the figure leaves out:

- Lines that only a refusal of the system reaches, which no input or setting brings about here: `mmap`, `mprotect` or `madvise` refused for pages the crate maps, `prctl(PR_SET_NO_NEW_PRIVS)` or `pthread_atfork` refused, `dup2` refused when a worker ends its streams, a thread the system starts but cannot join, a `write` that takes nothing or is interrupted, and standard streams the standard library did not make. A closed secret whose pages the system will not open again ends the process; the unit tests reach that refusal through a fault of the crate's own, and the end itself is left out. They are most of the lines missing in `src/os/unix.rs` and `src/os/linux.rs`.
- Races and older systems: a thread that ends between the listing of threads and the reading of its status, a descriptor closed between two looks at it, and the mark of a lock of all memory on a kernel before Linux 4.14.
- A worker that cannot write its profile: under a filter that refuses every opening for writing, the check "without /dev/null a worker that serves no more still ends its streams" runs, and the fallback to an ended pipe is not counted.
- A request or answer of 4 GiB or more, which a test cannot hold, and a second call of `serve` in one process.
- The code for Android, macOS, iOS, Windows and WebAssembly, which this build does not compile. The tests run on macOS and Windows as well, at every push, without a measurement of their lines.
- Files under `tests/`. The count includes the unit tests inside `src/`.

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

For the source fingerprint, hash each Rust file under `src/` and `tests/`, plus `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml`. Sort by repository-relative path in byte order. Hash the resulting manifest of lowercase SHA-256 digests, two spaces, the path, and a newline per entry.

## Coverage by source file

| File                      | Covered lines | Measured lines | Coverage |
| ------------------------- | ------------: | -------------: | -------: |
| `src/channels.rs`         |            40 |             40 |  100.00% |
| `src/input.rs`            |           137 |            137 |  100.00% |
| `src/os.rs`               |            56 |             56 |  100.00% |
| `src/os/linux.rs`         |           449 |            462 |   97.19% |
| `src/os/linux/seccomp.rs` |           145 |            145 |  100.00% |
| `src/os/unix.rs`          |           374 |            408 |   91.67% |
| `src/os/unix/forks.rs`    |            17 |             17 |  100.00% |
| `src/protect.rs`          |           404 |            405 |   99.75% |
| `src/protect/closed.rs`   |           131 |            132 |   99.24% |
| `src/protect/options.rs`  |           139 |            139 |  100.00% |
| `src/stack.rs`            |            98 |             98 |  100.00% |
| `src/worker.rs`           |           227 |            237 |   95.78% |
