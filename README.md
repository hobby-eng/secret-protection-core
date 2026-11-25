# secret-protection-core

[![CI](https://github.com/hobby-eng/secret-protection-core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hobby-eng/secret-protection-core/actions/workflows/ci.yml)
[![RustSec audit](https://github.com/hobby-eng/secret-protection-core/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/secret-protection-core/actions/workflows/audit.yml)
[![Build provenance: GitHub attestations](https://img.shields.io/badge/build%20provenance-GitHub%20attestations-2ea44f)](https://github.com/hobby-eng/secret-protection-core/attestations)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

`secret-protection-core` is a Rust library for protecting passwords, API tokens and private keys from exposure in swap files and crash dumps, and from other processes trying to read them from memory. An application can keep a secret in a protected buffer or run sensitive work in a separate process and require specific OS protections before sending it any data.

The crate requires Rust 1.99 or later. Add it from crates.io, or as a Git dependency pinned to a signed release tag; [Add the dependency](docs/API.md#add-the-dependency) shows both. See the [documentation index](docs/README.md).

| Section                                 | What it covers                                                |
| --------------------------------------- | ------------------------------------------------------------- |
| [Protected memory](#protected-memory)   | Buffers kept out of swap and crash dumps that wipe themselves |
| [Process isolation](#process-isolation) | Restrictions on the current process, and isolated workers     |
| [Platform support](#platform-support)   | What each system offers, and the tests behind it              |
| [Security reviews](#security-reviews)   | The audit reports and the fix history                         |
| [License](#license)                     | MIT or Apache-2.0                                             |

## Protected memory

If an application reads a 32-byte key from a file, it can read directly into a locked buffer. The caller receives the buffer and can pass `key.as_slice()` to the operation that needs the key.

```rust
use secret_protection_core::WorkArea;
use std::{error::Error, fs::File, io::Read, path::Path};

fn load_key(path: &Path) -> Result<WorkArea, Box<dyn Error>> {
    let mut key = WorkArea::locked(32)?;
    File::open(path)?.read_exact(key.as_mut_slice())?;
    Ok(key)
}
```

If the OS refuses the lock, `load_key` returns before opening the file. A short read returns an error. The buffer wipes its storage when dropped, including on a read error. The key file on disk has its own lifetime.

Use `WorkArea` for fixed-size data and `Secret` for input that grows up to a fixed capacity, such as a password. Locking keeps memory out of swap. If you also require dump exclusion or protection across a Unix fork, check those properties separately.

`ClosedSecret` asks the OS to make the buffer inaccessible between uses. If closure is required, check `is_closed()` before storing the secret and after each use. Windows unlocks a page it makes inaccessible, so there `ClosedSecret::locked` keeps the lock and leaves the pages open. On Unix, a computation can also run on a separate thread whose stack the library wipes after it exits. Avoid forking while that stack is active, and leave previously borrowed secret bytes unused in a continuing child. Work on the calling thread can clear what it left on the stack: `with_cleared_stack` overwrites 128 KiB below the caller once the work returns or panics, and `clear_stack` does the same on each thread of a pool.

A buffer wipe cannot reach copies held by a text field, clipboard or caller-owned string. An abrupt process exit can skip the wipe entirely.

## Process isolation

On Linux, for example, a desktop application can keep its file picker and network connections in the main process while a worker checks a password. The parent can require the worker to block new sockets and refuse to open files for writing. If the library cannot confirm those restrictions for the whole worker process, startup fails before the parent sends the password. `Worker::start_within` and `Worker::call_within` give the start and each call a deadline.

To guard the current process, call `Isolation::enter_requiring` before reading a secret. The report records which restrictions the OS confirmed and whether each applies to the calling thread or the whole process. A process that already runs other threads can put the restrictions on all of them with `Options::all_threads` from Linux 7.0, and `Isolation::require_process_wide` refuses unless each required restriction reaches every thread. A socket opened before isolation can still be usable. A program that saves files after it has read a secret can make a new folder with `WritableFolder::create` and enter with `Isolation::enter_with_folders`. Where that reports `FolderWrites` confirmed, the program can make files there and nowhere else, while descriptors opened before isolation stay usable; `OpenChannels::only` then checks that, as the calling thread sees it, no descriptor beyond the ones it names and no writable shared memory is still open.

A GUI can send individual keystrokes to a worker that holds the password in a `SecretLine`. The GUI sees each key event and needs only the character count back to draw the password field. On Linux and macOS, a worker on the terminal reads the terminal on its standard error, so the password bypasses the parent. The worker has no controlling terminal and so cannot type into the shell. There `read_hidden_line` reads the password with the echo off and restores the terminal after.

## Platform support

| Platform    | Available protections                                                                                                                         |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Linux       | Secret memory or anonymous pages, process and thread restrictions, and a worker. Support depends on the kernel, architecture and host policy. |
| Android     | Native memory buffers and restrictions on a dedicated native thread.                                                                          |
| macOS       | Native memory buffers, process dump controls, debugger restrictions, sandbox and worker.                                                      |
| iOS         | Native memory buffers and the process core-dump limit.                                                                                        |
| Windows     | Native buffers with working-set locking, exclusions from Windows Error Reporting, and an AppContainer worker without network capabilities.    |
| WebAssembly | Fixed-capacity heap buffers that wipe their own storage on drop. The browser controls paging and process isolation.                           |

CI runs the tests on Linux x86-64, Linux ARM64, macOS on Apple silicon and on Intel, Windows with the MSVC and the GNU toolchain, and WebAssembly in Node, and a release waits for all of them. Android and iOS are only compiled and checked with Clippy: no runner tests them yet, so what the table above says of them rests on the code and the systems' documentation, not on a run. CI also runs the tests on 32-bit x86 Linux (`i686`) and lints 32-bit ARM Linux, to catch errors of 32-bit sizes and of Linux without the seccomp filter; these two are tests, not supported platforms. The last coverage measurement, of the 0.2.0 source on 2026-11-25 during the remediation of AUD-018, ran 118 checks on Linux x86-64 and covered **94.55%** of the measured source lines (3,710 of 3,924). [Coverage report](docs/COVERAGE.md)

## Security reviews

AI reviewers cross-checked findings about memory protection and worker isolation across multiple revisions, then retested the fixes on the affected platforms. An independent human security audit is still outstanding. [Audit reports and fix history](docs/audits/README.md).

---

<a id="license"></a>
Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. Dependency licenses are listed in the [third-party notices](THIRD_PARTY_NOTICES.md).
