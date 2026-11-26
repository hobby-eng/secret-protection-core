# Test coverage

The Linux x86-64 run on 2026-11-26 covered **94.38%** (4,051 of 4,292 measured source lines). All 131 checks passed (63 unit tests, 34 isolation checks, 9 secret-memory checks and 25 worker checks).

## Measurement

Rust 1.99.1 and cargo-llvm-cov 0.9.1 measured the source of version 0.2.0 as it is released, with two test threads. The SHA-256 of its measured input manifest is `9a5066ae5c67e3a4c654552e2bec8753a714c8d10efc0d71eeb03196900caa81` (40 files). The run reported no profile mismatches.

## Scope and exclusions

The Linux x86-64 measurement includes unit tests for buffer bounds, guard pages, wiping, page permissions, protected stacks and isolation reports. It also includes child processes started by three integration suites.

| Suite                                      | What it checks                                                                                          |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| [Isolation](../tests/isolation/main.rs)    | OS restrictions, thread scope and the effects of entering isolation more than once.                     |
| [Secret memory](../tests/secret_memory.rs) | Page locking, dump exclusion, fork behavior and allocation failures.                                    |
| [Worker](../tests/worker.rs)               | Process identity, startup checks, request and reply limits, and collection of the child after shutdown. |

The nested PID-namespace check can report a skip if the host refuses `mlockall` or creation of a second PID namespace. A pass for the enclosing test alone does not establish that this branch ran. [Skip conditions](../tests/isolation/linux/roles.rs)

The percentage counts library source lines compiled for Linux x86-64. Integration test source files and code specific to other platforms are outside the denominator. Some uncovered lines handle Linux errors or alternative C library implementations.

CI also runs tests on Linux ARM64, macOS on Apple silicon and on Intel, Windows with the MSVC and the GNU toolchain, WebAssembly in Node, and, as a test rather than a supported platform, 32-bit x86 Linux. Android, iOS and 32-bit ARM Linux get compile-time checks with Clippy. The native macOS run at `e7b0d38` verified that the library collected a worker after the shutdown deadline. [CI configuration](../.github/workflows/ci.yml) · [Native run](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745920704)

## Reproduce on Linux

From the repository root, in bash, with the pinned toolchain.

```sh
mkdir -p target
export CARGO_TARGET_DIR="$(mktemp -d "$PWD/target/coverage.XXXXXXXX")"
export CARGO_LLVM_COV_TARGET_DIR="$CARGO_TARGET_DIR"
source <(cargo llvm-cov show-env --sh)
export RUSTFLAGS="-C llvm-args=-runtime-counter-relocation"
export LLVM_PROFILE_FILE="$CARGO_TARGET_DIR/spc-%p%c.profraw"
cargo test --locked --offline
cargo llvm-cov report --summary-only
```

`%p` gives each process its own profile. `%c` enables continuous profiling, so child processes can record counters after isolation removes their permission to open files. An exit-only profile can miss those executions. With `%c` each process maps its profile file shared and writable, which the channel check rightly names: the `shared-memory` check leaves that mapping out in a measured build.

For the source fingerprint, hash each Rust file under `src/` and `tests/`, plus `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml`. Sort by repository-relative path in byte order. Hash the resulting manifest of lowercase SHA-256 digests, two spaces, the path, and a newline per entry.

## Coverage by source file

| File                             | Covered lines | Measured lines | Coverage |
| -------------------------------- | ------------: | -------------: | -------: |
| `src/channels.rs`                |            54 |             54 |  100.00% |
| `src/input.rs`                   |           374 |            377 |   99.20% |
| `src/os.rs`                      |            89 |             89 |  100.00% |
| `src/os/linux.rs`                |           595 |            615 |   96.75% |
| `src/os/linux/landlock_layer.rs` |            49 |             49 |  100.00% |
| `src/os/linux/mappings.rs`       |            70 |             71 |   98.59% |
| `src/os/linux/seccomp.rs`        |           276 |            279 |   98.92% |
| `src/os/unix.rs`                 |           314 |            348 |   90.23% |
| `src/os/unix/child.rs`           |           125 |            146 |   85.62% |
| `src/os/unix/forks.rs`           |            23 |             23 |  100.00% |
| `src/os/unix/terminal.rs`        |           328 |            371 |   88.41% |
| `src/os/unix/worker.rs`          |           362 |            415 |   87.23% |
| `src/protect.rs`                 |           458 |            459 |   99.78% |
| `src/protect/closed.rs`          |           135 |            138 |   97.83% |
| `src/protect/folder.rs`          |           136 |            166 |   81.93% |
| `src/protect/options.rs`         |           148 |            148 |  100.00% |
| `src/stack.rs`                   |           175 |            175 |  100.00% |
| `src/worker.rs`                  |           340 |            369 |   92.14% |
