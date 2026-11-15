# secret-protection-core

> [!WARNING]
> **Draft, not ready for production.** The interface will still change: a policy that names each protection and a report of what took effect are being designed. Nobody outside the project has reviewed this crate.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

secret-protection-core keeps secrets in memory out of the places they leak to: swap, core dumps, child processes and other programs that read the memory of the process. It gives a program buffers for secrets in memory pages of their own, and a call that isolates the whole process against a secret leaving it. It has code for Linux, Android, macOS, iOS and Windows; in WebAssembly a secret is only wiped.

The [documentation index](docs/README.md) lists the guides; [How it works](docs/TECHNICAL.md) says what each system applies and what it does not cover.

## Contents

- [What it is for](#what-it-is-for)
- [What it does](#what-it-does)
- [Systems](#systems)
- [What it does not do](#what-it-does-not-do)
- [Use from Rust](#use-from-rust)
- [License](#license)

## What it is for

A program that holds a recovery phrase, a key or a password in memory leaves copies of it where an ordinary heap buffer goes: into the swap file when the system runs short of memory, into a crash dump, into a child process, and into the reach of other programs of the same user that open the process to read its memory. This crate closes those ways out for the buffers it gives and, when the program asks for it, for the process as a whole. It is shared by the programs of this workspace that hold secrets, so that each protection is written, fixed and tested once.

Similar crates cover parts of it: `secrets`, `secure-types` and `memsec` lock buffers and add guard pages, `secmem-proc` keeps dumps and debuggers away, and `landlock` and `seccompiler` restrict a Linux process; this crate builds its Landlock layer with `landlock`. It brings buffers, dumps, child processes and the isolation of the process together on five systems, and each buffer and each call reports what the system confirmed.

## What it does

| Task                                                   | Item               | What it applies                                                                               |
| ------------------------------------------------------ | ------------------ | --------------------------------------------------------------------------------------------- |
| Keep a secret in memory                                | `Secret`           | pages of its own, locked, out of core dumps and child processes, wiped on drop, never growing |
| Give a computation memory for its work                 | `WorkArea`         | the same for large areas, such as the memory of a password hash, without Linux secret memory  |
| Shut the process against a secret leaving it, for good | `Isolation::enter` | no core dumps, no reading of its memory by other programs, no new sockets, no file changes    |
| Write a secret to the terminal                         | `write_secret`     | past the standard library's buffer, which keeps the last bytes written and is never wiped     |

Every buffer is wiped with writes the compiler keeps (`zeroize`) and shows nothing of its bytes in its `Debug` text. Each one says what holds: `is_locked`, `is_out_of_dumps` and `is_out_of_children` report what the system confirmed when the pages were made, and `Isolation::enter` reads back every protection it applied. A refusal of the system, such as a lock beyond the lock limit, is reported, never hidden.

## Systems

| System                      | A secret's pages                                                         | The isolation of the process                                                              |
| --------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| Linux on x86-64 and AArch64 | secret memory (`memfd_secret`) where the kernel offers it, else as below | no core dumps, not dumpable, `no_new_privs`, a seccomp filter, Landlock, an empty network |
| Linux, other architectures  | `mlock`, out of core dumps, zeros in a child process                     | as above, Landlock instead of the filter                                                  |
| Android                     | as Linux, without secret memory                                          | the dump settings and the filter, on a native thread of its own                           |
| macOS                       | `mlock`, not given to a child process                                    | no core dumps, no debugger attaching, a sandbox without network or file writes            |
| iOS                         | as macOS                                                                 | no core dumps                                                                             |
| Windows                     | `VirtualLock`, out of error reports                                      | error reports without the heap, access lists that keep other programs out, low integrity  |
| WebAssembly                 | an ordinary heap buffer, wiped                                           | nothing, and it says so                                                                   |

[How it works](docs/TECHNICAL.md) has the details of each system and what each does not cover.

## What it does not do

It promises no secret ever reaches the disk: copies the program makes, stacks and registers, an image of the whole memory when the machine hibernates and snapshots of a virtual machine are beyond a library. Root, an administrator and a debugger attached before the isolation are not kept out. `Isolation::enter` changes the whole process for good: it is for a program, or a worker process, whose only work is with the secret, not for a library to call on its own.

## Use from Rust

```rust
use secret_protection_core::Secret;

// A secret of up to 64 bytes in pages of its own.
let mut secret = Secret::with_capacity(64);
secret.push(b"a secret, for the test only").unwrap();
assert_eq!(secret.as_bytes(), b"a secret, for the test only");
// What the system confirmed for these pages.
println!("locked: {}, out of dumps: {}", secret.is_locked(), secret.is_out_of_dumps());
// Dropping it wipes the bytes before the pages are given back.
```

## License

MIT or Apache-2.0, at your option. [Third-party notices](THIRD_PARTY_NOTICES.md) list the crates it uses.
