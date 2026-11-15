# secret-protection-core

Protection of secrets in memory and of the process that holds them, shared by the workspace's
programs. Workspace rules: `AGENTS.md` in the workspace root, and the coding guide it names (CORE,
RUST, TOOL, DOC).

Toolchain: Rust 1.99.1 (`rust-toolchain.toml`, with the targets of every system the crate has code
for). On the development machine set `CARGO_HOME` and `RUSTUP_HOME` as the workspace rules say, and
start every cargo command through `run-capped`.

Fast gates (CORE-43):

- `cargo fmt --check`
- `cargo clippy --all-targets --target <t> -- -D warnings` for each target of `rust-toolchain.toml`
  and the host
- `cargo test` (the isolation and secret-memory tests have a `main` of their own and start child
  processes)

CI (`.github/workflows/ci.yml`) runs these gates on x86-64 Linux and the tests on ARM Linux, macOS
and Windows; `audit.yml` holds `Cargo.lock` against the RustSec advisories.

Layout: `src/protect.rs` the public items and what each promises; `src/os.rs` the pages shared by
every system; `src/os/{unix,linux,apple,windows}.rs` the calls of each system. `unsafe` is allowed
only in `src/os*`, each block with a `SAFETY` comment. `docs/TECHNICAL.md` describes all of it and
must change with it.

Every buffer that holds secret bytes wipes them before it gives its pages back, never grows, and
shows nothing of them in `Debug`. A protection that the system refuses is reported, never hidden
and never an error.
