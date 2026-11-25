# API description

All application-facing types and functions are exported from the crate root, `secret_protection_core`. Sizes and limits are in bytes unless a method specifies characters.

| API group                                           | Types and functions                                                                                                                                                   |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Installation](#add-the-dependency)                 | Cargo dependency and Rust import                                                                                                                                      |
| [Secret buffers](#choose-a-buffer)                  | [`Secret`](#secret), [`ClosedSecret`](#closedsecret), [`WorkArea`](#workarea), `SecretError`                                                                          |
| [Process isolation](#require-isolation)             | [`Options`](#options), [`Isolation`](#isolation), [`Protection`](#protection-identifiers-and-report-fields), [outcomes, scope and errors](#outcomes-scope-and-errors) |
| [Open file descriptors](#inspect-open-channels)     | `open_channels`, `OpenChannels`, `Channel`, `ChannelKind`                                                                                                             |
| [Worker processes](#run-a-worker)                   | `serve`, `Worker`, `WorkerError`                                                                                                                                      |
| [Protected thread stacks](#protected-thread-stacks) | `run_on_protected_stack`, `StackProperties`, `StackRun`, `StackError`                                                                                                 |
| [Input and output](#handle-input-and-output)        | `SecretLine`, `Keystroke`, `KeystrokeBytes`, `read_hidden_line`, `LineEnd`, `write_secret`                                                                            |

[Error handling and formatting](#error-handling-and-formatting) covers the standard Rust traits used by these types. [Fuzz builds](#fuzz-builds-only) expose four additional test functions.

## Add the dependency

The crate is published on crates.io. It requires Rust 1.99 or newer and uses the 2024 edition. Its dependencies take compatible version ranges, so a program may resolve newer patch or minor releases than the versions in the repository's `Cargo.lock`, which are the ones the crate is tested with; keep the program's own lockfile.

```toml
[dependencies]
secret-protection-core = "0.1.1"
```

The signed release tag works as a source too: `secret-protection-core = { git = "https://github.com/hobby-eng/secret-protection-core", tag = "v0.1.1" }`.

For a local checkout, use `secret-protection-core = { path = "../secret-protection-core" }` in the same table. Import types and functions with `use secret_protection_core::{...};`.

To verify a downloaded release package against the tag, run the following command in the directory containing the file. [Download v0.1.1](https://github.com/hobby-eng/secret-protection-core/releases/tag/v0.1.1) The package on crates.io is the same file, so its SHA-256 matches the release's. The source digest is the commit of the signed tag, which `git verify-tag v0.1.1` checks and `git rev-parse 'v0.1.1^{commit}'` prints in a clone.

```sh
gh attestation verify secret-protection-core-0.1.1.crate \
  --repo hobby-eng/secret-protection-core \
  --signer-workflow hobby-eng/secret-protection-core/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.1 \
  --source-digest fcca0b234266163ab2d7e0fc8d5aa2a4a0f66940
```

## Choose a buffer

Use `Secret` for bytes of variable length up to a fixed capacity, `ClosedSecret` to restrict access between operations, and `WorkArea` for a computation that needs a fixed-size mutable slice. On normal drop in the owning process, each wipes its storage. Their `Debug` implementations hide the contents. Callers own any copies they make. Abrupt termination can bypass destructors.

### Secret

| Signature                                                                                         | Contract                                                                                                                                                |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `with_capacity(bytes: usize) -> Self`                                                             | Empty buffer with fixed capacity. Allocation attempts to lock the pages. Zero capacity is valid.                                                        |
| `locked(bytes: usize) -> Result<Self, SecretError>`                                               | Empty buffer. Returns `NotLocked` before accepting any bytes if the lock fails. Like `with_capacity` and `zeroed`, allocation failure ends the process. |
| `zeroed(bytes: usize) -> Self`                                                                    | Starts with length **and** capacity equal to `bytes`. Fill the existing bytes through `as_mut_bytes`. Locking is best effort.                           |
| `push(&mut self, bytes: &[u8]) -> Result<(), SecretError>`                                        | Appends the entire slice. `Full { capacity }` leaves contents and length intact.                                                                        |
| `truncate(&mut self, len: usize)`                                                                 | Wipes removed bytes. A length at or above the current length has no effect.                                                                             |
| `as_bytes(&self) -> &[u8]`                                                                        | Borrows the initialized contents. Use `as_bytes().len()` for the current length.                                                                        |
| `as_mut_bytes(&mut self) -> &mut [u8]`                                                            | Borrows the current contents for writing in place. The slice cannot extend the length.                                                                  |
| `as_str(&self) -> Option<&str>`                                                                   | Borrows valid UTF-8 as text. Returns `None` for other byte sequences.                                                                                   |
| `capacity(&self) -> usize`                                                                        | Maximum logical length in bytes.                                                                                                                        |
| `is_locked(&self) -> bool`, `is_out_of_dumps(&self) -> bool`, `is_out_of_children(&self) -> bool` | Report the three [allocation properties](#allocation-properties) independently.                                                                         |

```rust
use secret_protection_core::{Secret, SecretError};

fn main() -> Result<(), SecretError> {
    let mut token = Secret::locked(8)?;
    token.push(b"demo")?;
    assert_eq!(token.as_str(), Some("demo"));
    assert_eq!(token.push(b"extra"), Err(SecretError::Full { capacity: 8 }));
    assert_eq!(token.as_bytes(), b"demo");
    token.truncate(0);
    Ok(())
}
```

### ClosedSecret

| Signature                                                                                         | Contract                                                                                                                                            |
| ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `with_capacity(bytes: usize) -> Self`                                                             | Allocates an empty buffer and asks the OS to deny access to its pages.                                                                              |
| `locked(bytes: usize) -> Result<Self, SecretError>`                                               | Requires the memory lock. Check `is_closed()` separately if page closure is required. Allocation failure has the same behavior as `Secret::locked`. |
| `push(&mut self, bytes: &[u8]) -> Result<(), SecretError>`, `truncate(&mut self, len: usize)`     | Open for writing, append or wipe as for `Secret`, then request closure.                                                                             |
| `read<R>(&mut self, use_bytes: impl FnOnce(&[u8]) -> R) -> R`                                     | Opens for reading, passes the slice to the closure and returns its result.                                                                          |
| `write<R>(&mut self, change: impl FnOnce(&mut [u8]) -> R) -> R`                                   | Opens for writing. The closure can change the current bytes in place.                                                                               |
| `len(&self) -> usize`, `is_empty(&self) -> bool`, `capacity(&self) -> usize`                      | Current length, whether it is zero, and maximum length. These queries do not open the pages.                                                        |
| `is_closed(&self) -> bool`                                                                        | Whether the last confirmed permissions deny access in this process.                                                                                 |
| `is_locked(&self) -> bool`, `is_out_of_dumps(&self) -> bool`, `is_out_of_children(&self) -> bool` | Report the underlying allocation properties.                                                                                                        |

The guard requests closure after use, including when a callback unwinds. If closure matters to the caller, check before storing a secret and after each use. If the OS refuses to open the pages and their current permissions cannot serve the operation, the process aborts. If the owner cannot obtain write access to wipe the buffer on drop, the process aborts.

```rust
use secret_protection_core::ClosedSecret;
use std::{error::Error, io};

fn main() -> Result<(), Box<dyn Error>> {
    let mut token = ClosedSecret::locked(16)?;
    if !token.is_closed() {
        return Err(io::Error::other("cannot close token pages").into());
    }
    token.push(b"demo")?;
    if !token.is_closed() {
        return Err(io::Error::other("token pages remained open after append").into());
    }
    let length = token.read(|bytes| bytes.len());
    if !token.is_closed() {
        return Err(io::Error::other("token pages remained open after read").into());
    }
    assert_eq!(length, 4);
    Ok(())
}
```

### WorkArea

| Signature                                                                                         | Contract                                                                                                                     |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `new(bytes: usize) -> Option<Self>`                                                               | Zero-initialized scratch space, at least one byte even for `new(0)`. Returns `None` if allocation fails.                     |
| `locked(bytes: usize) -> Result<Self, SecretError>`                                               | Returns `NoMemory` if allocation fails and `NotLocked` if the pages could be allocated but could not be locked.              |
| `as_slice(&self) -> &[u8]`, `as_mut_slice(&mut self) -> &mut [u8]`                                | Borrow the whole work area for reading or writing.                                                                           |
| `is_locked(&self) -> bool`, `is_out_of_dumps(&self) -> bool`, `is_out_of_children(&self) -> bool` | Report the properties of this allocation. A large scratch area can exceed a process lock quota even if a small key succeeds. |

```rust
use secret_protection_core::{SecretError, WorkArea};

fn main() -> Result<(), SecretError> {
    let mut scratch = WorkArea::locked(4096)?;
    scratch.as_mut_slice()[..4].copy_from_slice(b"demo");
    assert_eq!(&scratch.as_slice()[..4], b"demo");
    Ok(())
}
```

`SecretError` implements `std::error::Error`. Its variants are `Full { capacity: usize }`, `NotLocked` and `NoMemory`. Match the variant to handle an append limit, a refused memory lock or a failed work-area allocation, respectively.

### Allocation properties

| Query                  | Meaning of `true`                                                                                                                                                                                                              |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `is_locked()`          | The allocation is locked against swap. A successful best-effort constructor alone gives no such guarantee.                                                                                                                     |
| `is_out_of_dumps()`    | Linux/Android exclude these pages from ordinary core dumps. Windows registers the region for exclusion from Windows Error Reporting. Apple platforms offer only a process-level core limit, so the page query returns `false`. |
| `is_out_of_children()` | A child receives none of the stored bytes through this mapping. On Unix it gets zeros or no mapping. On Windows a newly launched process has a separate address space.                                                         |

On WebAssembly the crate wipes its own heap buffers on normal drop. All three queries and `is_closed()` return `false`. On Linux, create the first secret or enter isolation before starting threads if you need the kernel secret-memory backend. Later allocations can still use locked anonymous pages.

After an ordinary Unix `fork`, a continuing child must leave inherited owners and previously borrowed byte slices alone. An inherited owner reports its memory protections as false, skips the parent's mapping on drop and aborts on fresh access to its bytes. Allocate a new buffer in the child only when the parent had one thread at the fork: a child of a process with threads may inherit a lock another thread held, and should only call `exec` or `_exit`. If the OS must withhold the original bytes, check `is_out_of_children()` in the parent before storing them.

## Require isolation

Enter isolation in the process that will handle the secret. Apply it before reading input and, where process-wide protection is required, before starting other threads, or with `Options::all_threads` when other threads are already running. Restrictions already applied stay in force even if a strict check returns an error; with `Options::all_threads` they can include the other threads' new restrictions, as the option's row says. Existing file descriptors can remain usable.

### Isolation

| Signature                                                                                          | Contract                                                                                                                   |
| -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `enter() -> Self`                                                                                  | Applies the default OS restrictions and returns the observed results.                                                      |
| `enter_with(options: Options) -> Self`                                                             | Also attempts the selected optional restrictions. Inspect the returned report before accepting input.                      |
| `enter_requiring(options: Options, required: &[Protection]) -> Result<Self, Missing>`              | Enters isolation, then checks that each required outcome is `Confirmed`.                                                   |
| `enter_with_folders(options: Options, folders: &[&WritableFolder]) -> Self`                        | As `enter_with`, and lets the program write beneath `folders` and nowhere else ([below](#grant-folders-for-writing)).      |
| `require(self, required: &[Protection]) -> Result<Self, Missing>`                                  | Checks an existing report and returns it on success. Does not apply or probe restrictions again.                           |
| `enter_requiring_process_wide(options: Options, required: &[Protection]) -> Result<Self, Missing>` | As `enter_requiring`, but each required protection and `WholeProcess` must also cover every thread of the process.         |
| `require_process_wide(self, required: &[Protection]) -> Result<Self, Missing>`                     | As `require`, with the rule of `enter_requiring_process_wide`.                                                             |
| `has(&self, protection: Protection) -> bool`                                                       | True when the recorded outcome is `Confirmed`. The named public boolean fields below are shortcuts on the returned report. |
| `outcome(&self, protection: Protection) -> Outcome`                                                | Reads the result for one protection.                                                                                       |
| `measures(&self) -> Vec<Measure>`                                                                  | One entry per protection in `Protection::ALL` order, including its scope and evidence.                                     |

`Isolation` records observations at entry. `require` and `enter_requiring` check outcomes only, so a restriction confirmed for the calling thread alone passes them. To require a restriction on **every thread**, use `require_process_wide` or `enter_requiring_process_wide`: each listed protection must have process `reach`, and `WholeProcess` must be confirmed as well. [Worker admission](#run-a-worker) applies the same rule. `Missing` lists every unmet protection at once.

This Linux example refuses to proceed unless the file-lock restriction, the ban on new sockets and whole-process isolation cover every thread.

```rust
use secret_protection_core::{Isolation, Options, Protection};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let required = [Protection::FileLocksRefused, Protection::NoNewSockets];
    let options = Options::new().refuse_file_locks();
    Isolation::enter_requiring_process_wide(options, &required)?;
    // Read secret input only after this check succeeds.
    Ok(())
}
```

### Grant folders for writing

Isolation forbids every file change. A program that must save files after it has read a secret can be granted folders to write in, on Unix systems:

| Signature                                                 | Contract                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WritableFolder::create(path) -> std::io::Result<Self>`   | Makes a new folder with mode 0700, refused when the path exists, and holds it open. Refused when the folder made was replaced before it was opened or is not the user's. The parent must be one that no one else can change: the folder made is found there by its name.                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `path(&self) -> &Path`, `is_private(&self) -> bool`       | The path it was made at, and whether only the user can reach it, as checked when it was made: false on a file system that keeps no Unix modes (FAT, exFAT, NTFS, many network mounts), whose mount sets the access. On macOS, whose sandbox grants a folder by its path, it is also false when an access list on the folder or above it allows anything to anyone, when it or a folder above it lies on a volume mounted to ignore owners, as many removable volumes are, or when a folder above it, up to the root, belongs to someone other than the user or root, or its group or others may write in it without the sticky bit: someone else could then reach the folder, or move it and put another at its path. |
| `as_raw_fd`, `as_fd`                                      | The descriptor that holds it, to name in `OpenChannels::only`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `Isolation::enter_with_folders(options, &[&folder, ...])` | Grants the folders and reports `FolderWrites`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

A folder is granted only when, at entry, it is still the folder made and empty, and only by the calling thread's first isolation, which in a process of one thread is the process's: Landlock layers, seccomp filters and the macOS sandbox only narrow what an earlier one allows, so a folder cannot be opened later, and a later call reports `FolderWrites` refused. Enter isolation once, after the program has made its folders and before it reads the secret.

Linux grants it with a Landlock rule beneath each folder for making files and folders, writing, removing, and from Landlock ABI 2 (Linux 5.19) links and renames between folders, which Landlock refuses whenever the file would gain a right by the move. ABI 1 refuses every link and rename between directories; within one directory they work. Without Landlock nothing is granted and the filter stays closed. With folders granted, the filter lets these calls through anywhere, and Landlock decides where:

- an open for writing only of a new file, `O_WRONLY | O_CREAT | O_EXCL`, optionally with `O_CLOEXEC`, `O_NOFOLLOW` and `O_LARGEFILE`, and a mode within 0600: `OpenOptions::new().write(true).create_new(true).mode(0o600)`;
- `mkdir` and `mkdirat` with a mode within 0700, as `DirBuilder::new().mode(0o700)` makes; `fs::create_dir` asks for 0777 and is refused;
- `link`, `linkat` without flags, `rename`, `renameat`, `renameat2` without flags or with `RENAME_NOREPLACE`, `unlink`, `unlinkat` and `rmdir`.

Everything else stays refused: opening an existing file for writing, `O_TRUNC`, `O_APPEND`, `O_TMPFILE`, symbolic links, devices, mode, owner, time and attribute changes, and links by descriptor (`AT_EMPTY_PATH`). Descriptors opened before isolation keep working, `ftruncate` included; a file made after isolation cannot be truncated from Landlock ABI 3 (Linux 6.2), which handles truncation and grants it nowhere. macOS grants it with a sandbox rule beneath each folder's real path for creating regular files and folders, writing data and removing what is beneath, not the folder itself. The sandbox cannot check modes or tell a new file from an old one, so files there can be written again; hard links stay refused. The rule names the path, not the folder: a folder moved away loses the grant, and another one put at that path would get it. Where `is_private` is true no one but the user and root can do that; where it is false another user may. The sandbox may also compare names without regard to letter case, so on a case-sensitive volume the rule can cover a sibling whose name differs only in case. Windows, Android, iOS and WebAssembly grant nothing and report `FolderWrites` as not offered or refused.

Every process of the user can read a granted folder, as any of the user's folders: a process started before isolation can read whatever is written there, in plain text too. Grant new folders for the program's own output, and check what else is open with [`OpenChannels::only`](#inspect-open-channels).

```rust
use secret_protection_core::{Isolation, Options, Protection, WritableFolder, open_channels};
use std::error::Error;
use std::os::fd::AsRawFd;

fn main() -> Result<(), Box<dyn Error>> {
    let folder = WritableFolder::create("design-files")?;
    // Only the user may reach it, and on macOS no one else may put another folder at its path.
    if !folder.is_private() {
        return Err("the folder is not private".into());
    }
    Isolation::enter_with_folders(Options::new(), &[&folder])
        .require_process_wide(&[Protection::FolderWrites, Protection::NoNewSockets])?;
    open_channels()?
        .only(&[0, 1, 2, folder.as_raw_fd()])
        .map_err(|unexpected| format!("open before the secret: {unexpected:?}"))?;
    // Read the secret, then save into folder.path() with new files of mode 0600.
    Ok(())
}
```

### Options

`Options::new() -> Options` and `Options::default()` leave all seven options off. Default isolation still runs. `new` and all seven builders are `const fn`. Each builder consumes `self` and returns the updated `Self`, so chain the calls or keep their return value. A builder requests a restriction. Put the corresponding `Protection` in the required list when failure must stop work.

| Builder                               | Protection            | Where it applies and what callers must allow for                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `refuse_file_locks(self) -> Self`     | `FileLocksRefused`    | Linux/Android. Refuses file locking through `flock` and the lock, lease and delegation commands of `fcntl`. Even read-only database operations may require a lock.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `refuse_sendmsg(self) -> Self`        | `SendmsgRefused`      | Linux/Android. Refuses `sendmsg` on existing sockets. This can break descriptor passing and desktop IPC.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `signals_to_self_only(self) -> Self`  | `SignalsToSelfOnly`   | Linux/Android. Restricts signals to the current process and refuses the `fcntl` owner commands and setting `O_ASYNC`, so signal-driven I/O fails. Job-control signals the kernel sends to the caller's process group from a controlling terminal stay outside it. A child of a later fork inherits the rule naming the parent, which it cannot lift: it can signal the parent and no other process, itself included (`raise` and `abort` too), and once it isolates itself again with this option, its own rule refuses the parent as well, so it can signal no process at all.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `all_threads(self) -> Self`           | `WholeProcess`        | Linux, for a process that already has other threads at entry; Android ignores it, as an app's Binder and runtime threads would break. From Landlock ABI 8 (Linux 7.0) the layer and then the seccomp filter go onto every thread at once (TSYNC), so those threads lose new sockets, file changes and the rest in the middle of their work. Below ABI 8 the layer stays on the calling thread, and so does the filter, whose rules count on the layer: everything reaches that thread alone. A kernel without Landlock puts the filter alone onto every thread. The option assumes the other threads hold no Landlock layer or seccomp filter of their own. The layer replaces another thread's own layer, which no call can see. The layer's TSYNC is tried once per process: before that try a filter that allows everything goes onto every thread, which the kernel refuses where a thread holds a filter the caller's does not descend from. Then, as on any later call that would need the layer's TSYNC again, the whole call stays on the calling thread, the layer included. A later call that needs none, the layer being on every thread already, can still put the filter alone onto every thread, which the kernel does whole or not at all. On a processor this crate writes no filter for, other than x86-64 and AArch64, the layer stays on the calling thread. A call that falls short after that, as when the filter exceeds the kernel's limit on filter instructions, leaves the other threads with more restrictions, never fewer: the caller's earlier filters, the allowing one, and the caller's new layer in place of their own. Repeated calls add nothing once both reached every thread. The empty network namespace still needs one thread. Read `whole_process` and each measure's `reach`. |
| `lock_all_memory(self) -> Self`       | `MemoryLocked`        | Linux/Android. Requests locking of current and future mappings. The OS lock quota applies. Explicitly unlocking memory later can leave the earlier success recorded.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `refuse_dynamic_code(self) -> Self`   | `DynamicCodeRefused`  | Windows. Requests a ban on dynamic executable code. JIT runtimes may stop working.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `microsoft_signed_only(self) -> Self` | `MicrosoftSignedOnly` | Windows. Subsequent DLL loads require a Microsoft signature. This can prevent an application from loading its own plug-ins.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

### Protection identifiers and report fields

`Protection::ALL` contains the following identifiers. Each row names the corresponding public `bool` on `Isolation`. `Protection` and `Isolation` are non-exhaustive. Use a fallback arm when matching `Protection`. `Isolation::default()` creates an empty report with false fields and `Unsupported` outcomes. It applies no restrictions.

| `Protection`          | `Isolation` field       | What the check covers                                                                                                                                                                                                                                                                |
| --------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `NoCoreDumps`         | `no_core_dumps`         | Unix core limit. Linux/Android also require a non-dumpable process. Windows error reports can include registers and stacks, so this measure is unsupported there.                                                                                                                    |
| `NoMemoryReading`     | `no_memory_reading`     | Platform checks on new access to process memory. Linux/Android can return `Unknown` when an outside tracer could be hidden. macOS checks debugger attachment. Windows checks access controls and debugger status. Handles already granted can retain access.                         |
| `NoNewSockets`        | `no_new_sockets`        | Linux/Android check new sockets and `io_uring`. On macOS socket creation can succeed and the sandbox denies bind or connect. On Windows this confirms an AppContainer token without capabilities, without probing a connection or checking loopback exemptions.                      |
| `EmptyNetwork`        | `empty_network`         | Linux namespace setup, no listed interface other than loopback and no IPv4 routes. The check omits IPv6 routes and interface flags.                                                                                                                                                  |
| `NoFileChanges`       | `no_file_changes`       | Linux/Android require the filter and a refused write-open; folders granted by `enter_with_folders` are the exception. macOS checks its sandbox, which permits certain terminal and null-device writes. Previously opened descriptors may still allow writes. Unsupported on Windows. |
| `SpeculationLimited`  | `speculation_limited`   | Linux/Android require both queried mitigations to be permanent or unnecessary. An unreadable state can give `Unknown`. Windows checks its side-channel mitigation policy.                                                                                                            |
| `WholeProcess`        | `whole_process`         | Whether isolation has process scope. Linux/Android check for a single thread at entry, or that the filter, and the layer where there is one, reached every thread: on Linux with `all_threads`, or by an earlier call made with one thread. Read each required measure’s own scope.  |
| `FileLocksRefused`    | `file_locks_refused`    | Linux/Android file-lock filter and probe.                                                                                                                                                                                                                                            |
| `SendmsgRefused`      | `sendmsg_refused`       | Linux/Android `sendmsg` filter and probe.                                                                                                                                                                                                                                            |
| `DynamicCodeRefused`  | `dynamic_code_refused`  | Windows dynamic-code policy, including opt-out checks.                                                                                                                                                                                                                               |
| `MicrosoftSignedOnly` | `microsoft_signed_only` | Windows policy for signatures on newly loaded DLLs.                                                                                                                                                                                                                                  |
| `SignalsToSelfOnly`   | `signals_to_self_only`  | Linux/Android filter restricts signal targets to this process.                                                                                                                                                                                                                       |
| `SignalsWithinLayer`  | `signals_within_layer`  | Linux Landlock signal scope (Linux 6.12 and later). The layer can include child processes.                                                                                                                                                                                           |
| `MemoryLocked`        | `memory_locked`         | Linux/Android process-wide memory lock at the time of the check.                                                                                                                                                                                                                     |
| `NoNewPrograms`       | `no_new_programs`       | Linux/Android executable-launch filter and probe. Windows child-process policy. macOS reports `Unknown` after sandbox entry and `Refused` if entry failed.                                                                                                                           |
| `NoPlantedLibraries`  | `no_planted_libraries`  | Windows extension-point and image-load policies and default DLL search directories. The application directory must be trusted. Explicit paths or custom search flags can select other locations.                                                                                     |
| `DesktopRestricted`   | `desktop_restricted`    | Windows job limits processes and restricts clipboard writes, other windows and desktop changes. Clipboard reads remain possible.                                                                                                                                                     |
| `FolderWrites`        | `folder_writes`         | Linux with Landlock, and macOS: writes go only beneath the folders `enter_with_folders` granted, in the forms [above](#grant-folders-for-writing).                                                                                                                                   |
| `LowIntegrity`        | `low_integrity`         | Windows primary token and effective tokens on the inspected threads were low integrity or lower. Later impersonation can change this.                                                                                                                                                |

On iOS the crate reports the core-size setting and whole-process scope. It does not install the macOS desktop sandbox. On WebAssembly all process isolation measures are `Unsupported`.

### Outcomes, scope and errors

| Report type | Values and fields                                                                                                                                                                                                                                                                                                                                                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Outcome`   | `Confirmed` means the entry check observed the protection. `Refused` means the attempt or check failed. `NotRequested` means the option was not requested and the check did not confirm it was already active. `Unsupported` means this target does not offer it. `Unknown` means the evidence could not establish the result. Only `Confirmed` satisfies a strict check. |
| `Reach`     | `Thread` covers the calling thread and threads it starts afterwards. `Process` covers every thread. Interpret scope as a guarantee only for a confirmed result.                                                                                                                                                                                                           |
| `Measure`   | `protection: Protection`, `outcome: Outcome`, `reach: Reach`, `evidence: &'static str`. Use the typed fields for decisions and the evidence text when displaying the result.                                                                                                                                                                                              |
| `Missing`   | `missing: Vec<Protection>` lists the unmet requirements once each in `Protection::ALL` order. `isolation: Isolation` retains the full report for inspection.                                                                                                                                                                                                              |

## Inspect open channels

`open_channels() -> std::io::Result<OpenChannels>` lists file descriptors visible to the calling thread on Unix, and the shared memory of the process that it can write. Both can include channels made before isolation, which stay usable after it: a socket, a file open for writing, memory shared with a process started before isolation, or a shared mapping of a file whose descriptor was closed. Another thread sharing the table can change it during or after inspection. Windows and WebAssembly return `io::ErrorKind::Unsupported`.

`OpenChannels::only(&self, expected: &[i32]) -> Result<(), OpenChannels>` is the strict check: `Ok` only when the inventory is complete, holds no descriptor outside `expected` and no shared mapping. Otherwise it returns what was unexpected. Call it after isolation, which keeps new sockets and file writes out, and before reading the secret; name in `expected` the program's own descriptors, such as the standard streams, output files opened before isolation and granted folders. It compares numbers only: a descriptor named there passes whatever it is, so check each by its purpose, for example the `kind` of the standard streams when they must be a terminal. It sees one moment, and on Linux the calling thread's descriptor table: a thread made with a table of its own is not seen, and only isolation with process scope (`require_process_wide`) keeps every thread from opening a new channel.

| Type            | Public fields and values                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `OpenChannels`  | `channels: Vec<Channel>` sorted by descriptor number, including open standard streams. `shared_mappings: Vec<SharedMapping>` sorted by address. `complete: bool` is false if some entries could not be listed or examined. In that case even empty lists are inconclusive.                                                                                                                                                                                         |
| `SharedMapping` | `start: usize`, `length: usize`, `name: String`. Shared memory the process can write, now or after `mprotect`: Linux takes the mappings with `sh` and `mw` in `/proc/self/smaps`, macOS the regions whose highest protection allows writing that map a file other than copy-on-write, or memory in a shared mode or with shared inheritance. This crate's own secret memory is left out by its address. Other Unix systems and iOS leave the inventory incomplete. |
| `Channel`       | `descriptor: i32`, `kind: ChannelKind`, `writable: Option<bool>`. `Some(true)` means open for writing, `Some(false)` means the descriptor was not opened for writing, and `None` means the mode could not be determined.                                                                                                                                                                                                                                           |
| `ChannelKind`   | `Socket`, `File`, `Pipe` (including FIFOs), `Terminal`, `Device`, `Directory`, `Other` or `Unknown`. A denied terminal ioctl can make a terminal appear as `Device`.                                                                                                                                                                                                                                                                                               |

```rust
use secret_protection_core::{open_channels, ChannelKind};
use std::io;

fn main() -> io::Result<()> {
    let snapshot = open_channels()?;
    if !snapshot.complete {
        return Err(io::Error::other("incomplete descriptor inventory"));
    }
    for channel in snapshot.channels {
        if channel.kind == ChannelKind::Socket {
            eprintln!("open socket on descriptor {}", channel.descriptor);
        }
    }
    Ok(())
}
```

## Run a worker

On Linux, macOS and Windows, the parent starts another instance of its own executable. Call `serve` first in `main`, before opening files or starting threads. If it returns `true`, return from `main`. The parent receives a `Worker` only after the clean-start check, process-wide `WholeProcess` confirmation, and process-wide confirmation for each requested protection.

| Signature                                                                                                            | Contract                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `serve(most: usize, answer: impl FnMut(&[u8]) -> Secret) -> bool`                                                    | Handles requests up to `most` bytes. The handler borrows each request for one call and returns an owned reply. Returns `true` for a recognized worker, including a failed worker startup. Returns `false` outside worker mode or if that role has already been claimed.                                                                                              |
| `Worker::start(options: Options, required: &[Protection]) -> Result<Worker, WorkerError>`                            | Starts a worker without terminal access. An empty required list still requires a clean start and whole-process isolation.                                                                                                                                                                                                                                            |
| `Worker::start_within(options: Options, required: &[Protection], deadline: Duration) -> Result<Worker, WorkerError>` | As `start`, with a deadline for the launch, the connection and the startup report. When it passes the start fails with `WorkerError::Start` of kind `TimedOut` and the worker is given up, as for `call_within`. Unix checks it again just before the launch. A deadline too far ahead for the clock to hold, such as `Duration::MAX`, waits without one.            |
| `Worker::start_on_terminal(options: Options, required: &[Protection]) -> Result<Worker, WorkerError>`                | Linux/macOS. The worker's standard error is this program's terminal, opened anew for reading and writing, or `/dev/null` when no standard stream is a terminal. The worker has no controlling terminal: it cannot type into the terminal (`TIOCSTI`), and `/dev/tty` does not open. Standard input and output carry the protocol.                                    |
| `isolation(&self) -> Isolation`                                                                                      | Returns the worker’s startup report.                                                                                                                                                                                                                                                                                                                                 |
| `call(&mut self, request: &[u8], most: usize) -> std::io::Result<Secret>`                                            | Sends one request and reads one response, with `most` as the maximum **reply** size. Both limits are bytes.                                                                                                                                                                                                                                                          |
| `call_within(&mut self, request: &[u8], most: usize, deadline: Duration) -> std::io::Result<Secret>`                 | As `call`, with a deadline for the whole exchange; an answer that arrives past it fails too. When it passes the call fails with `TimedOut` and the worker is given up: its pipes close, and it is terminated where a stable handle exists (Windows, Linux with a pidfd). A deadline too far ahead for the clock to hold, such as `Duration::MAX`, waits without one. |
| `end(self) -> bool`                                                                                                  | Consumes the worker, closes the transport and reports whether it ended. Dropping it also attempts shutdown if it has not already run.                                                                                                                                                                                                                                |

`WorkerError::Start(io::Error)` covers launch, transport and startup-protocol errors, including an unsupported mode or target. `WorkerError::Unclean` means the worker failed its startup cleanliness check: a descriptor above standard error, a session it could not leave, or on Linux another thread at its start. A worker ignores `Options::all_threads`. `WorkerError::Missing(Missing)` supplies the isolation report and the unmet requirements from the admission check. No application request has been sent in any of these cases.

On Unix, keep application output off the worker’s standard output. Startup inspects descriptors above standard error. Windows launches without handle inheritance and uses a named pipe. The executable and startup libraries must be accessible to the AppContainer. Worker launch is unsupported on Android, iOS and WebAssembly. Windows supports `start`, but does not offer the terminal mode.

```rust
use secret_protection_core::{serve, Options, Protection, Secret, Worker};
use std::{error::Error, io};

fn check_text(input: &[u8]) -> Secret {
    let mut reply = Secret::zeroed(1);
    reply.as_mut_bytes()[0] = u8::from(std::str::from_utf8(input).is_ok());
    reply
}

fn main() -> Result<(), Box<dyn Error>> {
    if serve(128, check_text) {
        return Ok(());
    }
    let mut worker = Worker::start(Options::new(), &[Protection::NoNewSockets])?;
    let reply = worker.call(b"public example", 1)?;
    assert_eq!(reply.as_bytes(), &[1]);
    if !worker.end() {
        return Err(io::Error::other("worker did not exit before the deadline").into());
    }
    Ok(())
}
```

The handler’s request limit and the parent’s reply limit are independent. Frames use a four-byte unsigned length. A request longer than `u32::MAX` fails locally with `InvalidInput` before sending, so the worker remains usable. A request above the handler’s limit ends service. A reply above the parent’s limit gives `InvalidData`. An exchange failure closes the transport, attempts shutdown and makes later calls fail with `BrokenPipe`. `start` and `call` wait without a deadline, so a worker that stops answering blocks the caller. Use `start_within` and `call_within` when the caller must get control back. A timed-out call gives the worker up and later calls fail with `BrokenPipe`; it returns after the shutdown described for `end` below, up to about two seconds past the deadline. On macOS and on Linux without a pidfd a worker given up keeps running until it next touches its pipes. On Windows the profile, the pipe and the process creation cannot be cut short: the deadline is read before and after them.

`end` waits up to one second. Windows and Linux with a spawn-time pidfd can then request termination and wait up to one more second. On macOS and on Linux without that handle, `false` can mean the worker is still running. A dedicated Unix waiter collects the child on exit. Leave the child’s wait status to the library on the POSIX fallback.

The parent retains its own request bytes. The transport uses best-effort `Secret::zeroed` buffers at the receiving end, and dropping them does not erase kernel pipe buffers. For input that must bypass the parent, the terminal worker can read the terminal on its standard error with `read_hidden_line`, which turns echo off, checks it and restores it. The worker has no job control, so the parent must stay the foreground job and leave the terminal alone meanwhile; it can also save the settings before the start and restore them after the worker ends. The worker can write any bytes to the terminal, control sequences included. Linux Landlock can deny terminal-control operations on a newly opened terminal.

## Protected thread stacks

```rust
use secret_protection_core::{run_on_protected_stack, StackError, StackProperties};

fn main() -> Result<(), StackError> {
    let required = StackProperties { locked: true, ..StackProperties::default() };
    let run = run_on_protected_stack(128 * 1024, required, || {
        let sample = *b"demo";
        sample.len()
    })?;
    assert!(run.properties.locked);
    assert_eq!(run.value, 4);
    Ok(())
}
```

`run_on_protected_stack<R: Send>(stack_bytes: usize, required: StackProperties, work: impl FnOnce() -> R + Send) -> Result<StackRun<R>, StackError>` runs synchronously from the caller's perspective. On Unix it rounds the size up to a page boundary, enforces the thread library’s minimum, checks the stack properties, runs the closure on a new thread, joins it and wipes the stack. Avoid `fork` anywhere in the process while this call is active. With unwinding enabled the caller receives a panic from the closure after cleanup. A panic-abort build exits immediately. Returned values, heap allocations and registers have separate lifetimes.

| Type              | Public fields and values                                                                                                                                                                                                                                                                                                   |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `StackProperties` | `locked: bool`, `out_of_dumps: bool`, `out_of_children: bool`. Set a flag to require that property before running the closure. `default()` requires none. Apple platforms cannot exclude individual stack pages from dumps.                                                                                                |
| `StackRun<R>`     | `value: R` is the closure's result. `properties: StackProperties` reports what protected the stack while it ran.                                                                                                                                                                                                           |
| `StackError`      | `Unsupported` on Windows and WebAssembly. `Size` if the requested size cannot be represented after rounding. `NotProtected(StackProperties)` reports the actual properties when a requirement is missing. `System(std::io::Error)` carries an allocation or thread setup failure. These errors occur before the work runs. |

### Clearing the calling thread's stack

`with_cleared_stack<T>(work: impl FnOnce() -> T) -> T` runs `work` in a frame of its own, below 2 KiB of stack it leaves unwritten, and then overwrites `CLEARED_STACK_BYTES` (128 KiB) of the calling thread's stack below the caller's frame with zeros, written once in place: when `work` returns, and also while a panic unwinds out of it. That is where `work` and what it called kept their locals: copies that moves leave behind, and the state of dependencies that never wipe it, such as the blocks and hashes of a password hash. `clear_stack()` does the overwrite alone, for each thread of a pool after the secret work it ran, such as the lanes of an Argon2 computation.

It is best effort: how deep the work wrote is not measured, and the thread needs 130 KiB of free stack. What `work` captures and returns passes through the frames above, which stay as they are: capture secrets by reference and return them in a `Secret`. Registers, heap copies and other threads' stacks stay as they are too, and a build that aborts on panic ends at the panic with nothing overwritten. WebAssembly overwrites nothing, as a stack that runs over there writes into the program's other memory with no guard page to stop it. `run_on_protected_stack` instead runs the work on a thread of its own, whose whole stack it wipes.

## Handle input and output

### SecretLine and Keystroke

Use `SecretLine` to collect text one Unicode scalar value at a time. A GUI can send one encoded `Keystroke` to a worker, keep the line there and display only the returned character count. The GUI, clipboard or input method may have already retained the typed character.

| Signature                                                           | Contract                                                                                                                                    |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `SecretLine::with_capacity(bytes: usize) -> SecretLine`             | Creates an empty UTF-8 line with fixed byte capacity. If locking is mandatory, check `line.as_secret().is_locked()` before accepting input. |
| `apply(&mut self, keystroke: Keystroke) -> Result<(), SecretError>` | Applies `Char(char)`, `RemoveLast` or `Clear`. A character that does not fit gives `Full { capacity }` and leaves the line intact.          |
| `push(&mut self, character: char) -> Result<(), SecretError>`       | Appends one complete UTF-8 scalar, using one to four bytes.                                                                                 |
| `remove_last(&mut self)`, `clear(&mut self)`                        | Wipe the last scalar or the entire line. Removing from an empty line has no effect.                                                         |
| `characters(&self) -> usize`                                        | Count of Unicode scalars. A single displayed grapheme can contain several scalars.                                                          |
| `as_secret(&self) -> &Secret`, `as_str(&self) -> &str`              | Borrow the backing buffer or its valid UTF-8 text.                                                                                          |
| `Keystroke::to_bytes(self) -> KeystrokeBytes`                       | Encodes one event. `Char` uses tag 1 followed by one UTF-8 scalar. `RemoveLast` and `Clear` are single bytes 2 and 3.                       |
| `KeystrokeBytes::as_bytes(&self) -> &[u8]`                          | Borrows the one-to-five bytes to send. The frame wipes its storage on drop. The original copyable `Keystroke` has no destructor.            |
| `Keystroke::from_bytes(bytes: &[u8]) -> Option<Keystroke>`          | Decodes exactly one complete event. Returns `None` for unknown tags, malformed UTF-8, extra or missing bytes.                               |

```rust
use secret_protection_core::{Keystroke, SecretLine};
use std::{error::Error, io};

fn main() -> Result<(), Box<dyn Error>> {
    let mut line = SecretLine::with_capacity(4);
    let frame = Keystroke::Char('é').to_bytes();
    let event = Keystroke::from_bytes(frame.as_bytes())
        .ok_or_else(|| io::Error::other("invalid key event"))?;
    line.apply(event)?;
    assert_eq!(line.characters(), 1);
    assert_eq!(line.as_secret().as_bytes().len(), 2);
    line.remove_last();
    assert_eq!(line.characters(), 0);
    Ok(())
}
```

### Hidden terminal input

`read_hidden_line(prompt: &str, line: &mut SecretLine) -> std::io::Result<LineEnd>` is exported on Unix and Windows. It reads one line typed on a terminal into `line` and shows none of it, not even dots. It returns `LineEnd::Entered` at Enter, `LineEnd::EndOfInput` at the end of the input and `LineEnd::Cancelled` at Ctrl+C. It empties `line` first, and again unless Enter took it, so a cancelled or failed read leaves nothing there. If the line must stay out of swap, check `line.as_secret().is_locked()` before the call. Calls from several threads take turns. The reading wipes the 16 KiB of stack below its frame after, so the calling thread needs that much free.

Before it writes `prompt`, it turns the terminal's echo, its own line editing and its signal keys off and reads the settings back; a terminal that does not report them off is refused before anything is read. Up to 64 KiB of keys waiting when the reading starts are read and dropped, and so are up to 64 KiB left when it ends, such as the rest of a pasted text that the shell would read next; keys that arrive after the settings are back go to the next reader. Input that cannot be dropped, more than that or on a Windows console that refuses, is an error: before the prompt nothing is read. The settings it found come back when the reading ends, by any key or error, and are read back; a failed restore, or input left that could not be dropped, is returned as an error even after a good line. A signal sent by another process, such as `kill`, can end the program with the echo still off, and so can Ctrl+Break on Windows; `stty sane` or a new console window restores the terminal.

On Unix it reads standard input when that is a terminal open for reading, else standard error, where `Worker::start_on_terminal` puts the terminal. The prompt goes to the first of these, standard error and standard output that is the same terminal open for writing, else to the first of them that is any terminal open for writing, as with `< /dev/tty`; when there is none, no prompt is shown. It opens nothing, so an isolated worker can call it. A worker has no controlling terminal, so the kernel's job control does not stop it: the program must be the foreground job and must not read the terminal itself while the worker reads, or the keys are split between them and part of the line can reach the shell. On Windows it reads the console of standard input and writes the prompt to the first of standard error and standard output that is a console it may write to; a file or pipe they were redirected to gets no prompt. A Windows worker has no console, so there the parent reads the line and sends it.

| Key                               | Effect                                                                                                      |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Enter, Enter on the keypad        | Takes the line.                                                                                             |
| Backspace, Ctrl+U                 | Remove the last character, or all of them.                                                                  |
| Ctrl+C                            | Cancels: `LineEnd::Cancelled`.                                                                              |
| Ctrl+D or Ctrl+Z on an empty line | Ends the input: `LineEnd::EndOfInput`.                                                                      |
| Arrow, function and mouse keys    | Nothing: their escape sequences are read to the end.                                                        |
| Escape alone, Tab, other controls | Nothing. After a lone Escape the next key counts as itself, except `[` and `O`, which begin a key sequence. |

With mouse tracking left on by another program in its oldest mode, a click beyond column or row 95 sends bytes that are not UTF-8 and ends the reading with `InvalidData`.

| Error kind     | Cause                                                                                                                                        |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `NotFound`     | Unix: neither standard input nor standard error is a terminal open for reading. Windows: standard input is no console.                       |
| `InvalidInput` | At Enter, the typed line is longer than `line` holds. Keys past the capacity are counted, so Backspace takes them back first.                |
| `InvalidData`  | The terminal sent bytes that are not UTF-8, or the console a lone surrogate.                                                                 |
| another kind   | The echo could not be turned off, the settings did not read back as restored, waiting input could not be dropped, or a read or write failed. |

```rust
use secret_protection_core::{LineEnd, SecretLine, read_hidden_line};
use std::io;

fn main() -> io::Result<()> {
    let mut line = SecretLine::with_capacity(256);
    if !line.as_secret().is_locked() {
        return Err(io::Error::other("the password would not stay out of swap"));
    }
    if read_hidden_line("Password: ", &mut line)? == LineEnd::Entered {
        println!("{} characters", line.characters());
    }
    Ok(())
}
```

### Standard output

`write_secret(text: &str) -> std::io::Result<()>` is exported on non-`wasm32` targets. It flushes Rust’s standard-output buffer and writes the supplied text directly, without adding a newline. Flush and write errors propagate. On Windows it writes UTF-16 to a console and UTF-8 to redirected output. Use it only when the output destination is intended to receive the text. It does not control terminal scrollback, redirected files or readers. On Unix a worker’s standard output is reserved for its protocol.

```rust
use secret_protection_core::write_secret;
use std::io;

fn main() -> io::Result<()> {
    write_secret("public example\n")
}
```

## Error handling and formatting

`SecretError`, `Missing`, `WorkerError` and `StackError` implement `Display` and `std::error::Error`, so callers can propagate them with `?`. Match on variants to retrieve an underlying I/O error or isolation report. `Protection` implements `Display` for human-readable labels. `Debug` hides keystroke contents but can show a line’s character count or a work area’s size. Formatting a borrowed slice or string can reveal the bytes directly. `StackRun<R>` uses the result type’s own `Debug` implementation when formatting its `value`.

## Fuzz builds only

Compiling the crate with `--cfg fuzzing` additionally exposes `secret_protection_core::fuzzing`. This module lets test harnesses exercise the worker parsers without starting a process. A normal dependency build does not export it.

| Function in `fuzzing`                              | Input and result                                                                                                                           |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `setting(text: &str) -> Option<(u32, bool, &str)>` | Parses the platform's startup setting and returns the option bits, terminal flag and channel suffix. Invalid settings return `None`.       |
| `options_again(bits: u32) -> u32`                  | Decodes the option bits and re-encodes the recognized ones. Unknown bits are discarded.                                                    |
| `report(bytes: &[u8]) -> Option<Isolation>`        | Parses the outcome and scope bytes from a startup report. The separate clean-start flag must be excluded. Invalid encodings return `None`. |
| `report_bytes(isolation: Isolation) -> Vec<u8>`    | Encodes the outcomes and their scope in protection order.                                                                                  |

```rust
use secret_protection_core::{fuzzing, Isolation};

fn main() {
    let snapshot = Isolation::default();
    let encoded = fuzzing::report_bytes(snapshot);
    assert_eq!(fuzzing::report(&encoded), Some(snapshot));
}
```
