# secret-protection-core

[![CI](https://github.com/hobby-eng/secret-protection-core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hobby-eng/secret-protection-core/actions/workflows/ci.yml)
[![RustSec audit](https://github.com/hobby-eng/secret-protection-core/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/secret-protection-core/actions/workflows/audit.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#tests-and-license)

This Rust library gives applications a place to hold passwords, keys and recovery phrases while they are in use. It can lock a buffer in memory, restrict the process that handles it and run secret operations in a separate worker. Each platform offers different protections. The application chooses which ones it requires before accepting a secret.

Start with the [platform and API guide](docs/TECHNICAL.md) for the guarantees of each call. The [documentation index](docs/README.md) also lists test results and audits.

## Contents

- [Store a secret](#store-a-secret)
- [Isolate a process](#isolate-a-process)
- [Use a worker](#use-a-worker)
- [Enter and display secrets](#enter-and-display-secrets)
- [Platform support](#platform-support)
- [Limits](#limits)
- [Use from Rust](#use-from-rust)
- [Tests and license](#tests-and-license)

## Store a secret

| Task                                       | API                                  | Behavior                                                                                                                   |
| ------------------------------------------ | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| Hold a password or key                     | `Secret`                             | Fixed capacity in bytes. Removing bytes wipes them, and dropping the buffer wipes its storage.                             |
| Require memory that stays out of swap      | `Secret::locked`, `WorkArea::locked` | Returns an error if the OS cannot provide locked memory. Use this before copying a secret into the buffer.                 |
| Keep a secret closed between operations    | `ClosedSecret`                       | Opens its pages during a read or write. Check `is_closed()` afterwards if closing is essential.                            |
| Allocate scratch space for a password hash | `WorkArea`                           | Starts filled with zeros and wipes the whole area on drop. Large areas may exceed the OS lock limit.                       |
| Run work on a protected thread stack       | `run_on_protected_stack`             | Requires the stack properties you specify and wipes the stack after the thread exits. Available on supported Unix systems. |

Native buffers have guard pages. Check `is_locked()`, `is_out_of_dumps()` and `is_out_of_children()` for the properties the OS granted to your allocation. WebAssembly uses an ordinary heap allocation that the library wipes on drop.

## Isolate a process

Call `Isolation::enter()` early in a process dedicated to handling secrets. `Isolation::measures()` reports each protection, its scope and the evidence for its outcome. For a program that must stop if a protection is unavailable, use `Isolation::enter_requiring`.

```rust,no_run
use secret_protection_core::{Isolation, Options, Protection};

let options = Options::new().refuse_file_locks().refuse_sendmsg();
let required = [Protection::NoFileChanges, Protection::NoNewSockets, Protection::WholeProcess];
let isolation = Isolation::enter_requiring(options, &required).expect("required protection");
```

Options include restricting signals and locking the whole process on Linux, and limiting executable code and DLL loading on Windows. Ordinary disk writes, a GUI toolkit or child processes can depend on capabilities that isolation takes away. Check open channels and choose protections before accepting input. [Options, outcomes and strict mode](docs/TECHNICAL.md#options-and-the-strict-mode).

## Use a worker

On Linux, macOS and Windows, `Worker::start(options, &required)` runs the same executable again. Call `serve(most, handler)` at the beginning of `main`, before other threads start. The parent receives a worker only after the startup check passes and every protection in `required` is confirmed. Both endpoints require confirmed whole-process isolation before dispatch. The parent then sends requests and sets a maximum reply size for each call.

Linux closes inherited nonstandard descriptors before the executable starts. macOS closes them through its spawn policy. Windows disables inheritance, uses a named pipe and retains only wait and termination rights on the worker. On Windows, use a worker when your application requires low integrity or protection against memory reads. Its parent can list the worker’s threads even when Windows hides that list from the worker itself. The worker checks their access rights and tokens before the parent can send a secret. A standalone process reports `Unknown` for a check it cannot complete. The executable and its startup libraries are trusted. [Worker startup and transport](docs/TECHNICAL.md#the-worker-process)

Startup and request–reply have no deadline. `Worker::end` closes the transport and reports whether the worker exited. Windows and Linux with a spawn-time pidfd can force termination. On macOS and older Linux paths a worker that outlives the grace period returns `false`. One waiting thread in the Unix parent collects the child when it eventually exits. On the POSIX fallback, give this library exclusive ownership of that child’s wait status.

## Enter and display secrets

A GUI can send each `Keystroke` to the worker and draw a dot for each character in its `SecretLine`. The input event still passes through the GUI and window system. Pasting can also leave a full copy in the clipboard or GUI process. For terminal input, `Worker::start_on_terminal` lets the worker read the password directly on Linux and macOS. The application handles echo. `write_secret` writes to standard output without putting the text in Rust's buffered output. It does not control where that stream goes. [Input and output](docs/TECHNICAL.md#typing-a-secret).

## Platform support

| Platform    | Memory and process support                                                                                                                                                                          |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Linux       | Kernel secret memory when available on x86-64 and AArch64, otherwise anonymous pages. Isolation can use seccomp, Landlock and separate namespaces according to the architecture, kernel and policy. |
| Android     | Anonymous pages and a filter on a dedicated native thread.                                                                                                                                          |
| macOS       | Anonymous pages, process dump controls, debugger restrictions and a sandbox.                                                                                                                        |
| iOS         | Anonymous pages and the process core-dump limit.                                                                                                                                                    |
| Windows     | Dedicated pages, working-set locking and per-region error-report exclusions where available. The worker runs in an AppContainer without network capabilities.                                       |
| WebAssembly | Fixed-capacity heap buffers and wiping on drop. The host controls process isolation and paging.                                                                                                     |

## Limits

A process that exits without running destructors skips the buffer wipe. Caller-owned copies, registers, clipboard contents, VM snapshots and previously granted access can outlive a library operation. On Windows, changing a process or thread access list does not revoke handles already opened by another process. In a Linux container, a debugger outside the PID namespace can be invisible.

On Unix, keep pre-fork byte references out of a continuing child. A closed-secret callback that returns in the child skips the parent’s page-permission change. Keep the entire process from forking while work is running on a protected stack. Check `is_out_of_children()` before writing sensitive data if the child must not inherit any bytes. [Security boundaries](docs/TECHNICAL.md#what-is-not-covered).

## Use from Rust

Depend on the reviewed Git revision or a local checkout. The crate manifest sets `publish = false`.

```rust
use secret_protection_core::Secret;

let mut secret = Secret::with_capacity(32);
secret.push(b"public example").unwrap();
assert_eq!(secret.as_bytes(), b"public example");
```

## Tests and license

Linux x86-64 line coverage was **95.07%** (2,468 of 2,596 measured lines) on 2026-11-15 at revision `a4fd4c5`. The run included the unit tests, all three integration programs and their workers. [Per-file coverage and platform scope](docs/COVERAGE.md).

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. [Third-party notices](THIRD_PARTY_NOTICES.md).
