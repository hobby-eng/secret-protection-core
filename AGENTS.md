# secret-protection-core

Read the workspace `AGENTS.md` and the coding guides it names before changing this library. The checkout uses Rust 1.99.1 with the targets in `rust-toolchain.toml`. On the workspace laptop, use the workspace Cargo and Rustup homes and prefix Cargo commands with `run-capped --`.

## Where to work

The public buffer and isolation APIs live in `src/protect.rs` and its submodules. The worker protocol is in `src/worker.rs`. The page abstraction lives in `src/os.rs`, and the platform calls are in the modules under `src/os/`. Keep unsafe production code in the OS modules, with a `SAFETY` comment for each unsafe block.

Secret owners use fixed-capacity storage, wipe it on normal destruction in its owning process, and keep the contents out of debug output. Best-effort APIs report the protections the OS granted. Strict calls return errors when required properties are missing. Check the [platform contracts](docs/TECHNICAL.md) when changing an allocation, worker or isolation guarantee. Update the [API description](docs/API.md) if the change affects a caller, and the [security policy](SECURITY.md) if it changes what an application can protect.

An audit, a review of findings or a remediation follow-up of this library follows the workspace's audit procedure in `../.github/audits/`: `FULL_AUDIT_GUIDE_V2.md` (the checks and their order; section 17 for Rust crates and every target they are built for), `AUDIT_STANDARD.md`, `AUDIT_TEMPLATE.md` and `audit-report.schema.json`, with this repository's [targets and audit notes](docs/audits/TARGETS.md). Reports, their JSON twins and their harnesses stay in `docs/audits/`.

## Checks

The main crate uses these fast gates (CORE-43).

- `cargo fmt --check`
- `cargo clippy --locked --all-targets -- -D warnings` for the host. Add `--target <triple>` before `--` for each target in `rust-toolchain.toml`.
- `cargo test --locked`. The integration binaries `isolation`, `secret_memory` and `worker` each use a custom main and run parts of the suite in child processes.
- `dprint check` for the Markdown, JSON, TOML and YAML, with the plugins `dprint.json` pins.

The CI workflow runs these checks on Linux x86-64, the stack-clearing tests in the release profile too, and runs the tests on Linux ARM64, macOS on Apple silicon and Intel, Windows with MSVC and GNU, and 32-bit x86 Linux, and the WebAssembly checks of `wasm/` in Node. The RustSec workflow checks the root, fuzz and `wasm/` lockfiles. The separate fuzz workspace has its own manifest and lockfile. To check it locally, use `cargo fmt --manifest-path fuzz/Cargo.toml --check`, `RUSTFLAGS="--cfg fuzzing" cargo clippy --locked --manifest-path fuzz/Cargo.toml --bins -- -D warnings`, and `cargo audit -f fuzz/Cargo.lock`.

Before a release or after changing data exchanged between processes or read from a terminal, run the sanitizer-backed fuzz targets that `fuzz/Cargo.toml` names: `setting`, `report`, `keystrokes`, `frames`, `roster` and `editor`. Run them in turn.

```sh
(
  set -e
  for target in setting report keystrokes frames roster editor; do
    cargo +nightly fuzz run --fuzz-dir fuzz --target x86_64-unknown-linux-gnu "$target" -- -max_total_time=90
  done
)
```

The setting and report targets use `--cfg fuzzing` to reach their parsers through `src/fuzzing.rs`. The keystrokes target calls the public input API. Follow [the coverage procedure](docs/COVERAGE.md) to include the worker and isolated subprocesses in a Linux line-coverage measurement.
