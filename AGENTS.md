# secret-protection-core

Read the workspace `AGENTS.md` and the coding guides it names before changing this library. The checkout uses Rust 1.99.1 with the targets in `rust-toolchain.toml`. On the workspace laptop, use the workspace Cargo and Rustup homes and prefix Cargo commands with `run-capped --`.

## Where to work

The public buffer and isolation APIs live in `src/protect.rs` and its submodules. The worker protocol is in `src/worker.rs`. The page abstraction lives in `src/os.rs`, and the platform calls are in the modules under `src/os/`. Keep unsafe production code in the OS modules, with a `SAFETY` comment for each unsafe block.

Secret owners use fixed-capacity storage, wipe it on normal destruction in its owning process, and keep the contents out of debug output. Best-effort APIs report the protections the OS granted. Strict calls return errors when required properties are missing. Check the [platform contracts](docs/TECHNICAL.md) when changing an allocation, worker or isolation guarantee. Update the [API description](docs/API.md) if the change affects a caller, and the [security policy](SECURITY.md) if it changes what an application can protect.

## Checks

The main crate uses these fast gates (CORE-43).

- `cargo fmt --check`
- `cargo clippy --locked --all-targets -- -D warnings` for the host. Add `--target <triple>` before `--` for each target in `rust-toolchain.toml`.
- `cargo test --locked`. The integration binaries `isolation`, `secret_memory` and `worker` each use a custom main and run parts of the suite in child processes.

The CI workflow runs these checks on Linux x86-64 and runs the tests on Linux ARM64, macOS and Windows. The RustSec workflow checks the root and fuzz lockfiles. The separate fuzz workspace has its own manifest and lockfile. To check it locally, use `cargo fmt --manifest-path fuzz/Cargo.toml --check`, `RUSTFLAGS="--cfg fuzzing" cargo clippy --locked --manifest-path fuzz/Cargo.toml --bins -- -D warnings`, and `cargo audit -f fuzz/Cargo.lock`.

Before a release or after changing data exchanged between processes, run the three sanitizer-backed fuzz targets, `setting`, `report` and `keystrokes`. Run all three in turn.

```sh
(
  set -e
  for target in setting report keystrokes; do
    cargo +nightly fuzz run --fuzz-dir fuzz --target x86_64-unknown-linux-gnu "$target" -- -max_total_time=90
  done
)
```

The setting and report targets use `--cfg fuzzing` to reach their parsers through `src/fuzzing.rs`. The keystrokes target calls the public input API. Follow [the coverage procedure](docs/COVERAGE.md) to include the worker and isolated subprocesses in a Linux line-coverage measurement.
