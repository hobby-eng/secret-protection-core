# Test coverage

The Linux x86-64 run on 2026-11-15 covered **95.18%** (2,471 of 2,596 measured source lines). All 84 checks passed (33 unit tests, 20 isolation checks, 9 secret-memory checks and 22 worker checks).

## Measurement

Rust 1.99.1 and cargo-llvm-cov 0.9.1 measured the working tree based on `e7b0d38fba46e45994cd8e7ecbdda185de9cee70`. The SHA-256 of its measured input manifest is `9503292b73ab2a39ede6083f838ff2715f464c539263a058e7d852b8ba46efc9`. An independent clean run of that commit before the local documentation and diagnostic wording changes also covered 2,471 of 2,596 lines. The current run reported no profile mismatches.

## Scope and exclusions

The Linux x86-64 measurement includes unit tests for buffer bounds, guard pages, wiping, page permissions, protected stacks and isolation reports. It also includes child processes started by three integration suites.

| Suite                                      | What it checks                                                                                          |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| [Isolation](../tests/isolation/main.rs)    | OS restrictions, thread scope and the effects of entering isolation more than once.                     |
| [Secret memory](../tests/secret_memory.rs) | Page locking, dump exclusion, fork behavior and allocation failures.                                    |
| [Worker](../tests/worker.rs)               | Process identity, startup checks, request and reply limits, and collection of the child after shutdown. |

The nested PID-namespace check can report a skip if the host refuses `mlockall` or creation of a second PID namespace. A pass for the enclosing test alone does not establish that this branch ran. [Skip conditions](../tests/isolation/linux/roles.rs)

The percentage counts library source lines compiled for Linux x86-64. Integration test source files and code specific to other platforms are outside the denominator. Some uncovered lines handle Linux errors or alternative C library implementations.

CI also runs tests on Linux ARM64, macOS and Windows. Android, iOS and WebAssembly receive compile-time checks. The native macOS run at `e7b0d38` verified that the library collected a worker after the shutdown deadline. [CI configuration](../.github/workflows/ci.yml) · [Native run](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745920704)

## Reproduce on Linux

From the repository root, in bash, with the pinned toolchain. The workspace laptop runs each Cargo command through `run-capped --`.

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

`%p` gives each process its own profile. `%c` enables continuous profiling, so child processes can record counters after isolation removes their permission to open files. An exit-only profile can miss those executions.

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
