# Targets and audit notes

What an audit of `secret-protection-core` needs beyond the workspace's audit guide, version 2, whose section 17, "Rust crates and native targets", applies here. The audit reconciles this file with `rust-toolchain.toml`, the workflows [ci.yml](../../.github/workflows/ci.yml), [release.yml](../../.github/workflows/release.yml) and [audit.yml](../../.github/workflows/audit.yml), the [README](../../README.md), the [API guide](../API.md) and the [platform guide](../TECHNICAL.md), and reports a mismatch. A report records the SHA-256 of this file.

## Target matrix

Three things stay apart here: whether the project supports a target (its documents claim it), whether a release audit must run it, and what CI does now. A result belongs to the report, never to this file. A supported target whose required run has no runner yet leaves a release audit INCOMPLETE, until a runner exists or the documents narrow the claim.

| Target | Support | Release audit runs it | CI now | Runner and minimum cases |
| --- | --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | Supported | Required | Clippy; tests; stack tests in release | Native Linux. Memory locks and dump policy, `fork`, seccomp and Landlock outcomes and their reach, user, network and IPC namespaces, folder grants, worker admission and shutdown, the worker's socket channel, pseudo-terminals. Record kernel features and partial skips. |
| `aarch64-unknown-linux-gnu` | Supported | Required | Tests; stack tests in release; no Clippy | ARM64 Linux. The filter's AArch64 table, the page size it runs with, speculation outcomes. A kernel with the advertised protection where the runner's lacks it. |
| `i686-unknown-linux-gnu` | Test only: the 32-bit sizes, not a supported platform | Optional; an ordinary audit runs it | Clippy; tests; stack tests in release | x86-64 host with the 32-bit C library. Sizes near `isize::MAX`, casts, the stack tests, which the 32-bit WebAssembly and ARM targets share. No seccomp filter on this target. |
| `armv5te-unknown-linux-gnueabi` | Test only: Linux without the seccomp filter, not a supported platform | Optional | Clippy only | Clippy, which compiles the Linux code paths without the filter. QEMU user mode with the ARM sysroot and `binfmt_misc` only for a closer look. |
| `aarch64-apple-darwin` | Supported | Required | Clippy; tests | ARM64 macOS. Mach region census, sandbox and folder scope, terminal isolation, child collection, 16 KiB pages. |
| `x86_64-apple-darwin` | Supported | Required | Clippy; tests | Intel macOS on `macos-15-intel`, GitHub's last Intel macOS runner, announced to go in 2027. The cases of the ARM64 macOS row with 4 KiB pages. |
| `x86_64-pc-windows-msvc` | Supported | Required | Tests; no Clippy | Native Windows. Memory and its lock under `ClosedSecret`, AppContainer worker, process and thread access lists, tokens, the named pipe and its nonce. |
| `x86_64-pc-windows-gnu` | Supported (in `rust-toolchain.toml`) | Required | Clippy only | Link with MinGW and run on Windows: calling conventions and Windows API errors, the cases of the MSVC row. |
| `aarch64-linux-android` | Supported | Required | Clippy only | An app process on a device or ARM64 emulator, with the NDK, API level and page size recorded: memory protections, the dedicated native thread's restrictions, refused outcomes, no worker. No runner yet. |
| `aarch64-apple-ios` | Supported | Required | Clippy only | A signed test app on a device: native buffers, the core-dump limit, no worker. No runner yet. |
| `aarch64-apple-ios-sim` | To decide | Required if supported | Not built | The simulator, for the cases of the device row it can show. |
| `wasm32-unknown-unknown` | Supported | Required | Clippy only | A harness `.wasm` in a pinned engine, as the probe of AUD-019 does in Node: heap buffers, input encoding, and `Unsupported` from every worker start, timed ones with a zero deadline included, from stacks and from channels. |

The README's "Linux" is built and tested with glibc only: musl, big-endian Linux and WASI are neither built nor tested, and stay out of support until the documents say otherwise.

## Fuzzing and analysis budgets

- Ordinary audit: each fuzz target for 5 minutes; Miri on the host, and on i686 and s390x for the memory and encoding code.
- Release audit: each fuzz target for 30 minutes, beside the 90-second runs of `release.yml`; AddressSanitizer on the Linux x86-64 suite.

## Platform properties

- The seccomp filter exists only for little-endian x86-64 and AArch64; elsewhere on Linux isolation reports it missing.
- Page sizes: 4 KiB on x86 Linux, Windows and Intel macOS, 16 KiB on Apple silicon, 4, 16 or 64 KiB on ARM64 Linux; record the device's or image's on Android.
- `ClosedSecret` on Windows: `locked` keeps its pages locked and open, `with_capacity` closes them and loses the lock.
- macOS logs through a buffer shared with the log daemon, which isolation brings in; the channel census leaves it out.

## Tests

- `tests/isolation`, `tests/secret_memory` and `tests/worker` have their own `main` and start this executable again in child roles: count from their output that every role ran, and give an emulator `binfmt_misc` so that the roles start.
- A check that a platform cannot make reports `ignored` or `not checked here` with its reason; list each in the evidence.
- The stack tests read `/proc/self/mem`, search at every byte, and run in the release profile too.
- The crate has no `cfg(miri)`: Miri runs the unit tests it can, by filter.

## Fuzzing, coverage and release

- Fuzz targets `keystrokes`, `report` and `setting` in `fuzz/`, with their own lockfile; `release.yml` runs each for 90 seconds with its pinned nightly and cargo-fuzz, an audit for the budgets above.
- Coverage: [the coverage report](../COVERAGE.md) gives the command and its input manifest; it covers Linux x86-64 only.
- `release.yml`, on a tag, runs `ci.yml`, `audit.yml` and the fuzz targets, then packages the crate, uploads the package as a workflow artifact and attests its build provenance. It does not check the tag's signature: the audit checks the signature, the tag's commit, the package bytes and the attestation.

## Permanent gaps

A real Windows console, macOS access lists and volumes mounted to ignore owners, the macOS file probe with its name taken, a repeated macOS grant's probe, the Android and iOS runs until a runner exists for them, and the Intel macOS run once GitHub retires `macos-15-intel`, until another runner exists or the documents narrow the claim.
