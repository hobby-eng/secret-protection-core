# secret-protection-core

[![CI](https://github.com/hobby-eng/secret-protection-core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hobby-eng/secret-protection-core/actions/workflows/ci.yml)
[![RustSec audit](https://github.com/hobby-eng/secret-protection-core/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/secret-protection-core/actions/workflows/audit.yml)
[![Build provenance: GitHub attestations](https://img.shields.io/badge/build%20provenance-GitHub%20attestations-2ea44f)](https://github.com/hobby-eng/secret-protection-core/attestations)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

`secret-protection-core` is a Rust library for protecting passwords, API tokens and private keys from exposure in swap files and crash dumps, and from other processes trying to read them from memory. An application can keep a secret in a protected buffer or run sensitive work in a separate process and require specific OS protections before sending it any data.

The crate requires Rust 1.99 or later. Add it to `Cargo.toml` as a Git dependency pinned to a reviewed revision. See the [documentation index](docs/README.md).

| Section                                 | Description                                                          |
| --------------------------------------- | -------------------------------------------------------------------- |
| [Protected memory](#protected-memory)   | Keep passwords and keys in locked buffers and handle copies safely.  |
| [Process isolation](#process-isolation) | Require OS restrictions before sending secrets to a worker.          |
| [Platform support](#platform-support)   | Check the protections available on the target OS.                    |
| [Security reviews](#security-reviews)   | See which findings were cross-checked and which fixes were retested. |
| [License](#license)                     | Find the crate and dependency licenses.                              |

## Protected memory

Use `Secret` for a password or key and `WorkArea` for temporary storage, such as the memory used by a password hash. Both wipe their own storage on normal drop. If a password must stay out of swap, call `Secret::locked` before reading it. The call returns an error if the OS refuses the lock. Dump exclusion and inheritance across a Unix fork have separate checks.

`ClosedSecret` asks the OS to make the buffer inaccessible between uses. If closure is required, check `is_closed()` before storing the secret and after each use. On Unix, a computation can also run on a separate thread whose stack the library wipes after it exits. Avoid forking while that stack is active, and leave previously borrowed secret bytes unused in a continuing child.

A buffer wipe cannot reach copies held by a text field, clipboard or caller-owned string. An abrupt process exit can skip the wipe entirely.

## Process isolation

On Linux, for example, a desktop application can keep its file picker and network connections in the main process while a worker checks a password. The parent can require the worker to block new sockets and refuse to open files for writing. If the library cannot confirm those restrictions for the whole worker process, startup fails before the parent sends the password.

To guard the current process, call `Isolation::enter_requiring` before reading a secret. The report records which restrictions the OS confirmed and whether each applies to the calling thread or the whole process. A socket opened before isolation can still be usable.

A GUI can send individual keystrokes to a worker that holds the password in a `SecretLine`. The GUI sees each key event and needs only the character count back to draw the password field. On Linux and macOS, a worker can read its controlling terminal directly so the password bypasses the parent. The application must disable and restore terminal echo.

## Platform support

| Platform    | Available protections                                                                                                                         |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Linux       | Secret memory or anonymous pages, process and thread restrictions, and a worker. Support depends on the kernel, architecture and host policy. |
| Android     | Native memory buffers and restrictions on a dedicated native thread.                                                                          |
| macOS       | Native memory buffers, process dump controls, debugger restrictions, sandbox and worker.                                                      |
| iOS         | Native memory buffers and the process core-dump limit.                                                                                        |
| Windows     | Native buffers with working-set locking, exclusions from Windows Error Reporting, and an AppContainer worker without network capabilities.    |
| WebAssembly | Fixed-capacity heap buffers that wipe their own storage on drop. The browser controls paging and process isolation.                           |

Native CI runs tests on Linux x86-64, Linux ARM64, macOS and Windows. CI checks that the Android, iOS and WebAssembly targets compile. On 2026-11-15, all 84 checks passed on Linux x86-64 and covered **95.18%** of the measured source lines (2,471 of 2,596).

## Security reviews

AI reviewers cross-checked findings across multiple revisions and retested the fixes. The 15 published reports cover memory protection, worker isolation and platform-specific behavior. An independent human security audit is still outstanding. [Audit reports and fix history](docs/audits/README.md).

---

<a id="license"></a>
Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. Dependency licenses are listed in the [third-party notices](THIRD_PARTY_NOTICES.md).
