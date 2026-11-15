# How secret-protection-core works

This document describes what the crate applies on each system, what it does not cover, and how it is tested. The documentation of each public item says the same at the place of the code, with every system call named.

## Contents

- [Principles](#principles)
- [Where things are in the code](#where-things-are-in-the-code)
- [A secret's pages](#a-secrets-pages)
- [The work area](#the-work-area)
- [The isolation of the process](#the-isolation-of-the-process)
- [The secret writer](#the-secret-writer)
- [What changed from the copies](#what-changed-from-the-copies)
- [What is not covered](#what-is-not-covered)
- [Tests](#tests)
- [What is planned](#what-is-planned)

## Principles

- **A buffer protects itself, always.** Every buffer for secret bytes lives in pages of its own, is wiped before the pages are given back, never grows, and shows nothing of its bytes in its `Debug` text. No switch turns this off.
- **The whole process changes only when the program asks.** `Isolation::enter` changes the process for good and refuses things a general program needs, such as writing files. A library never calls it on its own.
- **Report, never pretend.** Each buffer says what the system confirmed when its pages were made, and `Isolation::enter` reads back every protection it applied: a field is true only when reading it back confirmed it. A refusal of the system is reported, never an error.
- **The calls of each system in a module of their own.** `unsafe` code lives only there, each block with the reason it is sound.

## Where things are in the code

| Module              | What it holds                                                                                                |
| ------------------- | ------------------------------------------------------------------------------------------------------------ |
| `src/protect.rs`    | `Secret`, `WorkArea`, `Isolation`, `write_secret`, `SecretError`: what each promises                         |
| `src/os.rs`         | `Pages`, the memory shared by every system, read and written in one place; the heap buffer of WebAssembly    |
| `src/os/unix.rs`    | private anonymous mappings, `mlock`, `madvise`, `minherit`, the core-dump limit, the secret writer           |
| `src/os/linux.rs`   | secret memory, the dump settings, the seccomp filter, the Landlock layer, the empty network (Linux, Android) |
| `src/os/apple.rs`   | the isolation of macOS and iOS: the dump limit, the debugger, the sandbox                                    |
| `src/os/windows.rs` | committed regions, `VirtualLock` and the working set, error-report exclusion, access lists, integrity        |

## A secret's pages

`Secret::with_capacity(bytes)` maps pages of its own for the buffer; `Secret::zeroed(bytes)` does the same and opens all of them for writing in place. The pages are zero when made. Its capacity is fixed: a `push` that does not fit is refused with `SecretError::Full` and writes nothing, so the buffer never moves and never leaves a copy behind. `truncate` wipes what it cuts, and dropping the buffer wipes every page before it is unlocked and given back.

| System                       | The pages                                                 | Out of swap     | Out of core dumps        | Out of a child process           |
| ---------------------------- | --------------------------------------------------------- | --------------- | ------------------------ | -------------------------------- |
| Linux on x86-64 and AArch64  | secret memory (`memfd_secret`), when the kernel offers it | by construction | by construction          | `MADV_DONTFORK`, checked         |
| Linux otherwise, and Android | a private anonymous mapping                               | `mlock`         | `MADV_DONTDUMP`          | `MADV_WIPEONFORK`: zeros         |
| macOS and iOS                | a private anonymous mapping                               | `mlock`         | no call for single pages | `minherit(VM_INHERIT_NONE)`      |
| Windows                      | a committed region                                        | `VirtualLock`   | error-report exclusion   | a new process maps nothing of it |
| WebAssembly                  | a heap buffer                                             | no              | no                       | no child processes               |

Secret memory is kept out of the kernel's direct map: no other process, root included, reads it through `/proc/PID/mem`, `process_vm_readv` or `PTRACE_PEEKDATA`, and the machine does not hibernate while it exists. Its descriptor is opened with `O_CLOEXEC` and closed once the pages are mapped; every page is charged at once, so that a lock limit shows as a fallback to anonymous pages, not as a signal at the first write. A lock beyond `RLIMIT_MEMLOCK` leaves the pages as they are; Windows first grows the working set, under a lock that makes reading and setting it one step.

`is_locked`, `is_out_of_dumps` and `is_out_of_children` say what the system confirmed for these pages. On macOS no call keeps single pages out of a core dump: the process as a whole writes none once it is isolated.

## The work area

`WorkArea::new(bytes)` gives the pages of a computation that holds secrets, such as the memory of Argon2id: the same as a secret's, but never secret memory, so that a large area does not keep the machine from hibernating. They are locked only when the lock limit holds all of them, which also commits them; a refused lock leaves them unlocked, and `WorkArea::is_locked` says so. `None` answers when the system refuses the pages.

## The isolation of the process

`Isolation::enter()` applies, for good, what the system offers against a secret leaving the process, and returns what reads back as holding. A program calls it before it reads a secret; a worker process that does only the work with the secret is the right place for it. Descriptors and handles opened before the call stay usable, a socket or a file open for writing among them.

| System                        | What it applies                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Linux                         | `RLIMIT_CORE` 0 (both limits), not dumpable, `no_new_privs`; on x86-64 and little-endian AArch64 a seccomp filter that refuses new sockets, io_uring, `ptrace`, changes of the file system and every `ioctl` but the terminal's, and answers `ENOSYS` to newer calls; a Landlock layer where the kernel has it, made with the `landlock` crate, which also refuses connections to UNIX sockets made outside it; an empty network namespace when the process has one thread |
| Android                       | the same dump settings and filter, without Landlock and the namespace, for the calling thread only, which must be a native thread of its own                                                                                                                                                                                                                                                                                                                               |
| macOS                         | `RLIMIT_CORE` 0, `ptrace(PT_DENY_ATTACH)` unless a debugger is already attached, a sandbox without network or file writes                                                                                                                                                                                                                                                                                                                                                  |
| iOS                           | `RLIMIT_CORE` 0                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Windows                       | error reports without the heap, an access list of the process and of its threads that keeps other programs of the user out, low integrity                                                                                                                                                                                                                                                                                                                                  |
| WebAssembly and other systems | nothing; every field is false                                                                                                                                                                                                                                                                                                                                                                                                                                              |

The filter and the Landlock layer are installed once per thread: a further call finds the filter the thread already holds, from its own call or from the thread that started it, and adds no layer, so that the kernel's limits on filters and layers are not used up. The filter marks itself: it answers a `prctl` option that no kernel has with an error number of its own (4001), which the call reads before it installs anything. A filter that someone else installed, as every Android app and many containers run under, gives no such answer, and this crate's filter is added to it. Where no filter is written, what an earlier call of the thread or of the process recorded counts instead. The documentation of `Isolation::enter` names every call each system makes and what each does not cover.

## The secret writer

`write_secret(text)` writes to standard output past the standard library's buffer, which keeps the last bytes written and is never wiped: it flushes that buffer first, so that public output written before comes first, then writes the caller's bytes without a copy of its own. On a Windows console its UTF-16 copy lives in a `Secret`.

## What changed from the copies

The crate replaces two identical copies in `mhfe_core` and `stego-core`. Its first version moved them without changing what they do, with their tests, and then fixed five things a review found:

1. The macOS probe of file writes opened a predictable path with `File::create`, which could truncate a file, or the target of a link, at that path when the sandbox had not taken hold, and then removed the path. It now makes only a new file (`create_new`) and removes only what it made.
2. The descriptor of Linux secret memory was opened without `O_CLOEXEC`: a program that another thread started before the descriptor was closed would have got it.
3. The answers of `MADV_WIPEONFORK` and `minherit` were dropped, while the documentation promised that a child process gets none of the bytes. `is_out_of_children` now reports them.
4. Every call of `Isolation::enter` installed another seccomp filter and Landlock layer, which use up limits of the kernel. A thread that holds this crate's filter, from its own call or from the thread that started it, now gets no further layer. A filter that someone else installed does not count: the first check took any filter for this crate's, so that an Android app, which always runs under the system's filter, got none of this crate's.
5. Windows read the working set and set it again in two steps, so that threads making pages at once could lose a change, and every later drop gave back more than was taken. The two steps are now one, under a lock.

## What is not covered

- Copies the program makes of a secret, stacks and registers, an image of the whole memory when the machine hibernates (except while Linux secret memory exists), and snapshots of a virtual machine.
- Root, an administrator (`SeDebugPrivilege`), `CAP_SYS_PTRACE`, and a debugger or a `/proc/PID/mem` descriptor opened before the isolation.
- On Windows, error reports still hold the threads' stacks and registers.
- On Android, the crash handler makes the process dumpable again for its tombstone.

## Tests

The unit tests check the buffers: what fits and what is refused, that truncating wipes, that the pages report locks, dump exclusion and child protection where each system gives them, that a zeroed secret is zero on every page, and that `Debug` hides the bytes.

Two test programs have a `main` of their own, because the isolation needs a process of one thread and the counting allocator a process without other threads; each starts itself again in a role as a child process. `isolation` checks from outside that an isolated thread is refused what the filter names and keeps what it needs, that a process of one thread is isolated as a whole, that further calls read back the same and add no seccomp filter (as the kernel counts them in `/proc/thread-self/status`), nor a call in a thread that an isolated thread started, that a process started under a filter of someone else's still gets this crate's, once, that threads and a work area still work after it, that a UNIX socket opened before cannot connect to an abstract address outside the layer, and that a secret is written after the buffered public output. `secret_memory` checks where the pages lie as the system reports them (locked, `MADV_DONTDUMP`, secret memory), that a secret works under every lock limit and says whether it is locked, that a work area lies on pages of its own, and that six hundred secrets in a row each give back their error-report exclusion.

The tests run on Linux. Clippy checks the crate for Linux, Android, macOS, iOS, Windows and WebAssembly; the code for the other systems is not run here.

## What is planned

A policy that names each protection and a report of what took effect, for each one with its scope (the buffer, the thread, the process) and how it was confirmed: one call that a program makes before it reads a secret, the protections that change the process for good as options of their own, and a strict mode that stops before a secret is read when a required protection is missing. A buffer whose requirements are checked before the secret is copied into it, and buffers for the work of other crates of the workspace, such as the decoder of reed-solomon-core.
