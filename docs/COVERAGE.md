# Test coverage

On 2026-11-15 UTC the tests covered **89.09%** of the source lines that LLVM reports for the Linux x86-64 build (1,755 of 1,970). The run passed 20 unit tests and 36 checks of the three test programs `isolation`, `secret_memory` and `worker`. One more worker check passes in an ordinary run and cannot run under the measurement.

## Measurement

Rust 1.99.1 and cargo-llvm-cov 0.9.1 measured the Linux build on kernel 7.0.0-43-generic, x86-64. The measured source is the working tree that follows commit `370c651b6ef03a8f15ed17330b1e86e9e817a804`; the SHA-256 fingerprint of its inputs is `5d8d8671beb8ce60af6dff3cbeaf78d852c6d15a6b0bba3f2e5e43556e85e11b`.

The tests start child processes that isolate themselves and can then write no file, so a profile written when a process ends would be lost. The counters are therefore synced to the profile file as they change (`%c` in its name, with LLVM's `-runtime-counter-relocation`), and such a child is counted.

What the figure leaves out:

- The worker's own side. A worker starts with an empty environment, so it has no profile file: `serve`, the closing of inherited descriptors and the leaving of the terminal run in every worker check and are not counted. They are most of the lines missing in `src/worker.rs` and `src/os/unix.rs`.
- The worker check "a worker gets nothing of its parent's but its pipes". LLVM's profiling runtime puts a variable of its own into the worker's environment, which the check refuses, as it should. It passes without the instrumentation.
- The code for Android, macOS, iOS, Windows and WebAssembly, which this build does not compile. Its tests have not run on those systems, so there is no measurement for them.
- Files under `tests/`. The count includes the unit tests inside `src/`.

## Reproduce on Linux

From the repository root, in bash, with the pinned toolchain. The workspace laptop runs each Cargo command through `run-capped --`.

```sh
export CARGO_TARGET_DIR="$PWD/target/coverage"
source <(cargo llvm-cov show-env --sh)
export RUSTFLAGS="-C llvm-args=-runtime-counter-relocation"
export LLVM_PROFILE_FILE="$CARGO_TARGET_DIR/spc-%p%c.profraw"
cargo llvm-cov clean --workspace
cargo test --locked --offline -- --skip "nothing of its parent's"
cargo llvm-cov report --summary-only
```

For the source fingerprint, hash each Rust file under `src/` and `tests/`, plus `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml`. Sort by repository-relative path in byte order. Hash the resulting manifest of lowercase SHA-256 digests, two spaces, the path, and a newline per entry.

## Coverage by source file

| File                      | Covered lines | Measured lines | Coverage |
| ------------------------- | ------------: | -------------: | -------: |
| `src/channels.rs`         |            40 |             40 |  100.00% |
| `src/input.rs`            |           117 |            120 |   97.50% |
| `src/os.rs`               |            38 |             41 |   92.68% |
| `src/os/linux.rs`         |           396 |            431 |   91.88% |
| `src/os/linux/seccomp.rs` |           137 |            137 |  100.00% |
| `src/os/unix.rs`          |           257 |            326 |   78.83% |
| `src/protect.rs`          |           368 |            378 |   97.35% |
| `src/protect/closed.rs`   |           116 |            129 |   89.92% |
| `src/protect/options.rs`  |            76 |            101 |   75.25% |
| `src/stack.rs`            |            81 |             88 |   92.05% |
| `src/worker.rs`           |           129 |            179 |   72.07% |
