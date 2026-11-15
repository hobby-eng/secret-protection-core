# secret-protection-core

> [!WARNING]
> **Draft, not ready for production.** The interface will still change. The macOS and Windows code has not yet run on those systems, and nobody outside the project has reviewed this crate.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

secret-protection-core keeps secrets in memory out of the places they leak to: swap, core dumps, child processes and other programs that read the memory of the process. It gives a program buffers for secrets in memory pages of their own, a call that isolates the process against a secret leaving it, and a worker process that does the secret work apart from the rest of the program. It has code for Linux, Android, macOS, iOS and Windows; in WebAssembly a secret is only wiped.

The [documentation index](docs/README.md) lists the guides; [How it works](docs/TECHNICAL.md) says what each system applies and what it does not cover.

Line coverage on Linux x86-64, measured on 2026-11-15, is **89.09%** for the unit tests and the three test programs (source fingerprint `5d8d8671`). [Test scope and per-file results](docs/COVERAGE.md).

## Contents

- [What it is for](#what-it-is-for)
- [What it does](#what-it-does)
- [On by default, and what a program turns on](#on-by-default-and-what-a-program-turns-on)
- [A worker process](#a-worker-process)
- [Typing a secret](#typing-a-secret)
- [Systems](#systems)
- [What it does not do](#what-it-does-not-do)
- [Use from Rust](#use-from-rust)
- [License](#license)

## What it is for

A program that holds a recovery phrase, a key or a password in memory leaves copies of it where an ordinary heap buffer goes: into the swap file when the system runs short of memory, into a crash dump, into a child process, and into the reach of other programs of the same user that open the process to read its memory. This crate closes those ways out for the buffers it gives and, when the program asks for it, for the process as a whole. It is shared by the programs of this workspace that hold secrets, so that each protection is written, fixed and tested once.

Similar crates cover parts of it: `secrets`, `secure-types` and `memsec` lock buffers and add guard pages, `secmem-proc` keeps dumps and debuggers away, and `landlock` and `seccompiler` restrict a Linux process; this crate builds its Landlock layer with `landlock`. It brings buffers, dumps, child processes and the isolation of the process together on five systems, and each buffer and each call reports what the system confirmed.

## What it does

| Task                                                   | Item                      | What it applies                                                                                                      |
| ------------------------------------------------------ | ------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Keep a secret in memory                                | `Secret`                  | pages of its own, locked, out of core dumps and child processes, wiped on drop, never growing                        |
| Keep it closed between uses                            | `ClosedSecret`            | the same, with pages that refuse every access but during a use, where the system closes them; `is_closed` says       |
| Give a computation memory for its work                 | `WorkArea`                | the same for large areas, such as the memory of a password hash, without Linux secret memory                         |
| Shut the process against a secret leaving it, for good | `Isolation::enter`        | no core dumps, no reading of its memory by other programs, no new sockets, no file changes, no other program started |
| Write a secret to the terminal                         | `write_secret`            | past the standard library's buffer, which keeps the last bytes written and is never wiped                            |
| Do the secret work in a process of its own             | `Worker`, `serve`         | the program started again, isolated as a whole before it gets anything                                               |
| Collect a password typed in a window                   | `SecretLine`, `Keystroke` | one keystroke at a time, in protected pages, so that the window never holds it                                       |

Every buffer is wiped with writes the compiler keeps (`zeroize`), lies between guard pages that refuse every access, and shows nothing of its bytes in its `Debug` text. Each one says what holds: `is_locked`, `is_out_of_dumps` and `is_out_of_children` report what the system confirmed when the pages were made, and `Isolation::enter` reads back each protection where the system lets it, and otherwise goes by the answer of the call that applied it. Each protection comes back with one of five outcomes: confirmed, refused, not asked for, not offered on this system, or unknown, when the system gave the call no way to check. Only a confirmed protection counts as holding. A refusal of the system, such as a lock beyond the lock limit, is reported, never hidden, and `Secret::locked` and `WorkArea::locked` refuse unlocked pages before a secret is put in them.

## On by default, and what a program turns on

Whatever does not keep a usual program from working is on, with no switch; what may stop one, or makes every use slower, is the program's choice and off by default.

| Protection                                                                                                                 | On by default                                        | How a program turns it on                                   | Systems                             |
| -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------- |
| Pages of its own, wiped on drop, guard pages, no bytes in `Debug`                                                          | yes, always                                          | `Secret`, `WorkArea`                                        | all                                 |
| Locked, out of core dumps and child processes                                                                              | yes, where the system allows                         |                                                             | Linux, Android, macOS, iOS, Windows |
| Refuse pages that are not locked, before the secret is put in                                                              | no                                                   | `Secret::locked`, `WorkArea::locked`                        | all                                 |
| Pages closed between uses                                                                                                  | no: two system calls per use                         | `ClosedSecret`                                              | Linux, Android, macOS, iOS, Windows |
| The isolation of the process: no dumps, no memory reading, the filter, Landlock, the sandbox, the job, side-channel limits | when the program calls it                            | `Isolation::enter`                                          | per system, as below                |
| Refuse file locks                                                                                                          | no: SQLite and other databases need them             | `Isolation::enter_with(Options::new().refuse_file_locks())` | Linux, Android                      |
| Refuse `sendmsg`                                                                                                           | no: Wayland and D-Bus need it                        | `Options::refuse_sendmsg`                                   | Linux, Android                      |
| No new executable code                                                                                                     | no: a web view or a just-in-time compiler needs it   | `Options::refuse_dynamic_code`                              | Windows                             |
| Only DLLs signed by Microsoft                                                                                              | no: the program's own DLLs and graphics drivers fail | `Options::microsoft_signed_only`                            | Windows                             |
| Signals only to the process itself; without it Landlock keeps them inside its layer from Linux 6.12                        | no: children can't be signalled                      | `Options::signals_to_self_only`                             | Linux, Android                      |
| The whole process out of swap                                                                                              | no: needs a lock limit that covers the process       | `Options::lock_all_memory`                                  | Linux, Android                      |
| Secret work on a thread with a protected stack, refused when the stack lacks what the program requires                     | no                                                   | `run_on_protected_stack`                                    | Linux, Android, macOS, iOS          |
| What is still open after isolation, and whether the list is complete                                                       | when asked                                           | `open_channels`                                             | Linux, Android, macOS, iOS          |
| Each protection's outcome, reach and what the call observed                                                                | when asked                                           | `Isolation::measures`, `Isolation::outcome`                 | all                                 |
| Stop when a required protection is missing                                                                                 | no                                                   | `Isolation::enter_requiring(options, &[Protection::…])`     | all                                 |
| A separate worker process                                                                                                  | no: it changes how a program is built                | `Worker::start`, `serve`                                    | Linux, macOS, Windows               |

```rust,no_run
use secret_protection_core::{Isolation, Options, Protection};

// A command line program that uses no database and no desktop bus, and that refuses to read a
// secret without the filter and Landlock.
let options = Options::new().refuse_file_locks().refuse_sendmsg();
let required = [Protection::NoFileChanges, Protection::NoNewSockets, Protection::NoMemoryReading];
let isolation = Isolation::enter_requiring(options, &required).expect("isolation");
```

## A worker process

A program with a window, or one that wants the strongest isolation, does the secret work in a worker. `Worker::start` starts the program again. Before it reads anything, the worker closes every descriptor it inherited but its pipes, leaves its parent's terminal, isolates itself as a whole and reports each protection's outcome. The parent sends a request only when the worker says its start was clean and every protection the parent requires is confirmed; otherwise it ends the worker first: `WorkerError::Unclean` or `WorkerError::Missing`.

The worker shares no memory with the parent, inherits no descriptor but its pipes, gets an empty environment and no terminal (`Worker::start_on_terminal` keeps the terminal, for a password read in the worker). On Windows it runs in an AppContainer without capabilities, which keeps it from the network. The program's `main` calls `serve(most, answer)` first, where `most` is the longest request the worker takes; a program that reaches `Worker::start` in a worker is refused, so it never starts itself without end. An answer should hold what the parent shows or saves, never the password or the key.

A call that fails ends the worker before it returns: an answer longer than the caller allows, a request longer than `most`, or a broken pipe. Ending a worker never waits for ever: one that does not end within a second of its pipes closing is killed, and `Worker::end` says whether it ended. A program that may no longer signal other processes cannot kill a worker and leaves it behind. Starting a worker and waiting for an answer have no deadline of their own. Android and iOS start no worker; an Android app can declare an isolated service (`android:isolatedProcess`) in its manifest.

## Typing a secret

An ordinary text field keeps copies of what is typed in buffers of its toolkit or web view that no program can wipe. In the terminal, the worker reads the password itself, so that the parent never holds it. In a window, the field sends each key as a `Keystroke` to the worker the moment it is pressed, in bytes that wipe themselves once sent (`Keystroke::to_bytes`), keeps only how many characters there are to draw dots, and the worker collects them in a `SecretLine`; pasting goes through the program's own code to the worker, never through the field. The keyboard input itself passes through the window system, which a library cannot change: under X11 every program of the user can read the keys.

## Systems

| System                      | A secret's pages                                                                                                            | The isolation of the process                                                                                                        |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Linux on x86-64 and AArch64 | secret memory (`memfd_secret`) where the kernel offers it and the process had one thread when it first asked, else as below | no core dumps, not dumpable, `no_new_privs`, Spectre limits, a seccomp filter, Landlock, empty network and IPC                      |
| Linux, other architectures  | `mlock`, out of core dumps, zeros in a child process                                                                        | as above, Landlock instead of the filter                                                                                            |
| Android                     | as Linux, without secret memory                                                                                             | the dump settings, Spectre limits and the filter, on a native thread of its own                                                     |
| macOS                       | `mlock`, not given to a child process                                                                                       | no core dumps, no debugger attaching, a sandbox that refuses all but reading files and the terminal                                 |
| iOS                         | as macOS                                                                                                                    | no core dumps                                                                                                                       |
| Windows                     | `VirtualLock`, out of error reports                                                                                         | no extension points or child processes, no planted libraries, side-channel isolation, a restricted job, access lists, low integrity |
| WebAssembly                 | an ordinary heap buffer, wiped                                                                                              | nothing, and it says so                                                                                                             |

[How it works](docs/TECHNICAL.md) has the details of each system and what each does not cover.

## What it does not do

A buffer is wiped when it is dropped, so a process that ends without running its drops (built with `panic = "abort"`, or ended by a signal) leaves its secrets to the locked pages and the dump settings alone. It does not promise that a secret never reaches the disk: copies the program makes, stacks and registers, an image of the whole memory when the machine hibernates and snapshots of a virtual machine are beyond a library. Root, an administrator and a debugger attached before the isolation are not kept out, and the answer says so for a debugger it can see; in a container, whose PID namespace hides a debugger outside it, the answer is unknown. On Windows the network stays open in the process that calls `Isolation::enter`: only an administrator, or a worker in an AppContainer, closes it. On Linux, `sendmsg` through a socket opened before, file locks, and signals to the children a process starts stay unless the program turns the options on. `Isolation::enter` changes the whole process for good: it is for a program, or a worker process, whose only work is with the secret, not for a library to call on its own.

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
