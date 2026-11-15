# Test coverage

On 2026-11-15 UTC the tests covered **90.22%** of the source lines that LLVM reports for the Linux x86-64 build (1,900 of 2,106). The run passed 22 unit tests and 40 checks of the three test programs `isolation`, `secret_memory` and `worker`. One more worker check passes in an ordinary run and cannot run under the measurement.

## Measurement

Rust 1.99.1 and cargo-llvm-cov 0.9.1 measured the Linux build on kernel 7.0.0-43-generic, x86-64. The measured source is the working tree that follows commit `f89d0bf7578cdf3d9e9acc616fb3f1f6a71f9886`; the SHA-256 fingerprint of its inputs is `6c6c37593c6fa0c9f871aeeffa3ab601f39ad42c7865c1dfc27ce1a5958712c6`.

The tests start child processes that isolate themselves and can then write no file, so a profile written when a process ends would be lost. The counters are therefore synced to the profile file as they change (`%c` in its name, with LLVM's `-runtime-counter-relocation`), and such a child is counted.

What the figure leaves out:

- The worker's own side. A worker starts with an empty environment, so it has no profile file: `serve`, the closing of inherited descriptors and the leaving of the terminal run in every worker check and are not counted. They are most of the lines missing in `src/worker.rs` and `src/os/unix.rs`.
- The worker check "a worker gets nothing of its parent's but its pipes". LLVM's profiling runtime puts a variable of its own into the worker's environment, which the check refuses, as it should. It passes without the instrumentation.
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
| `src/os/linux.rs`         |           426 |            462 |   92.21% |
| `src/os/linux/seccomp.rs` |           145 |            145 |  100.00% |
| `src/os/unix.rs`          |           323 |            392 |   82.40% |
| `src/protect.rs`          |           368 |            378 |   97.35% |
| `src/protect/closed.rs`   |           116 |            129 |   89.92% |
| `src/protect/options.rs`  |            76 |            101 |   75.25% |
| `src/stack.rs`            |            81 |             88 |   92.05% |
| `src/worker.rs`           |           170 |            210 |   80.95% |
