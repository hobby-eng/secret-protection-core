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
| [Input and output](#handle-input-and-output)        | `SecretLine`, `Keystroke`, `KeystrokeBytes`, `write_secret`                                                                                                           |

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

After an ordinary Unix `fork`, a continuing child must leave inherited owners and previously borrowed byte slices alone. An inherited owner reports its memory protections as false, skips the parent's mapping on drop and aborts on fresh access to its bytes. Allocate a new buffer in the child. If the OS must withhold the original bytes, check `is_out_of_children()` in the parent before storing them.

## Require isolation

Enter isolation in the process that will handle the secret. Apply it before reading input and, where process-wide protection is required, before starting other threads. Restrictions already applied stay in force even if a strict check returns an error. Existing file descriptors can remain usable.

### Isolation

| Signature                                                                                          | Contract                                                                                                                   |
| -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `enter() -> Self`                                                                                  | Applies the default OS restrictions and returns the observed results.                                                      |
| `enter_with(options: Options) -> Self`                                                             | Also attempts the selected optional restrictions. Inspect the returned report before accepting input.                      |
| `enter_requiring(options: Options, required: &[Protection]) -> Result<Self, Missing>`              | Enters isolation, then checks that each required outcome is `Confirmed`.                                                   |
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

### Options

`Options::new() -> Options` and `Options::default()` leave all six optional restrictions off. Default isolation still runs. `new` and all six builders are `const fn`. Each builder consumes `self` and returns the updated `Self`, so chain the calls or keep their return value. A builder requests a restriction. Put the corresponding `Protection` in the required list when failure must stop work.

| Builder                               | Protection            | Where it applies and what callers must allow for                                                                                                                                                                                                                                                                         |
| ------------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `refuse_file_locks(self) -> Self`     | `FileLocksRefused`    | Linux/Android. Refuses file locking through `flock` and the lock, lease and delegation commands of `fcntl`. Even read-only database operations may require a lock.                                                                                                                                                       |
| `refuse_sendmsg(self) -> Self`        | `SendmsgRefused`      | Linux/Android. Refuses `sendmsg` on existing sockets. This can break descriptor passing and desktop IPC.                                                                                                                                                                                                                 |
| `signals_to_self_only(self) -> Self`  | `SignalsToSelfOnly`   | Linux/Android. Restricts signals to the current process and refuses the `fcntl` owner commands and setting `O_ASYNC`, so signal-driven I/O fails. Job-control signals the kernel sends to the caller's process group from a controlling terminal stay outside it. A subsequent fork inherits the rule naming the parent. |
| `lock_all_memory(self) -> Self`       | `MemoryLocked`        | Linux/Android. Requests locking of current and future mappings. The OS lock quota applies. Explicitly unlocking memory later can leave the earlier success recorded.                                                                                                                                                     |
| `refuse_dynamic_code(self) -> Self`   | `DynamicCodeRefused`  | Windows. Requests a ban on dynamic executable code. JIT runtimes may stop working.                                                                                                                                                                                                                                       |
| `microsoft_signed_only(self) -> Self` | `MicrosoftSignedOnly` | Windows. Subsequent DLL loads require a Microsoft signature. This can prevent an application from loading its own plug-ins.                                                                                                                                                                                              |

### Protection identifiers and report fields

`Protection::ALL` contains the following identifiers. Each row names the corresponding public `bool` on `Isolation`. `Protection` and `Isolation` are non-exhaustive. Use a fallback arm when matching `Protection`. `Isolation::default()` creates an empty report with false fields and `Unsupported` outcomes. It applies no restrictions.

| `Protection`          | `Isolation` field       | What the check covers                                                                                                                                                                                                                                           |
| --------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NoCoreDumps`         | `no_core_dumps`         | Unix core limit. Linux/Android also require a non-dumpable process. Windows error reports can include registers and stacks, so this measure is unsupported there.                                                                                               |
| `NoMemoryReading`     | `no_memory_reading`     | Platform checks on new access to process memory. Linux/Android can return `Unknown` when an outside tracer could be hidden. macOS checks debugger attachment. Windows checks access controls and debugger status. Handles already granted can retain access.    |
| `NoNewSockets`        | `no_new_sockets`        | Linux/Android check new sockets and `io_uring`. On macOS socket creation can succeed and the sandbox denies bind or connect. On Windows this confirms an AppContainer token without capabilities, without probing a connection or checking loopback exemptions. |
| `EmptyNetwork`        | `empty_network`         | Linux namespace setup, no listed interface other than loopback and no IPv4 routes. The check omits IPv6 routes and interface flags.                                                                                                                             |
| `NoFileChanges`       | `no_file_changes`       | Linux/Android require the filter and a refused write-open. macOS checks its sandbox, which permits certain terminal and null-device writes. Previously opened descriptors may still allow writes. Unsupported on Windows.                                       |
| `SpeculationLimited`  | `speculation_limited`   | Linux/Android require both queried mitigations to be permanent or unnecessary. An unreadable state can give `Unknown`. Windows checks its side-channel mitigation policy.                                                                                       |
| `WholeProcess`        | `whole_process`         | Whether isolation has process scope. Linux/Android check for a single thread at entry. Read each required measure’s own scope.                                                                                                                                  |
| `FileLocksRefused`    | `file_locks_refused`    | Linux/Android file-lock filter and probe.                                                                                                                                                                                                                       |
| `SendmsgRefused`      | `sendmsg_refused`       | Linux/Android `sendmsg` filter and probe.                                                                                                                                                                                                                       |
| `DynamicCodeRefused`  | `dynamic_code_refused`  | Windows dynamic-code policy, including opt-out checks.                                                                                                                                                                                                          |
| `MicrosoftSignedOnly` | `microsoft_signed_only` | Windows policy for signatures on newly loaded DLLs.                                                                                                                                                                                                             |
| `SignalsToSelfOnly`   | `signals_to_self_only`  | Linux/Android filter restricts signal targets to this process.                                                                                                                                                                                                  |
| `SignalsWithinLayer`  | `signals_within_layer`  | Linux Landlock signal scope (Linux 6.12 and later). The layer can include child processes.                                                                                                                                                                      |
| `MemoryLocked`        | `memory_locked`         | Linux/Android process-wide memory lock at the time of the check.                                                                                                                                                                                                |
| `NoNewPrograms`       | `no_new_programs`       | Linux/Android executable-launch filter and probe. Windows child-process policy. macOS reports `Unknown` after sandbox entry and `Refused` if entry failed.                                                                                                      |
| `NoPlantedLibraries`  | `no_planted_libraries`  | Windows extension-point and image-load policies and default DLL search directories. The application directory must be trusted. Explicit paths or custom search flags can select other locations.                                                                |
| `DesktopRestricted`   | `desktop_restricted`    | Windows job limits processes and restricts clipboard writes, other windows and desktop changes. Clipboard reads remain possible.                                                                                                                                |
| `LowIntegrity`        | `low_integrity`         | Windows primary token and effective tokens on the inspected threads were low integrity or lower. Later impersonation can change this.                                                                                                                           |

On iOS the crate reports the core-size setting and whole-process scope. It does not install the macOS desktop sandbox. On WebAssembly all process isolation measures are `Unsupported`.

### Outcomes, scope and errors

| Report type | Values and fields                                                                                                                                                                                                                                                                                                                                                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Outcome`   | `Confirmed` means the entry check observed the protection. `Refused` means the attempt or check failed. `NotRequested` means the option was not requested and the check did not confirm it was already active. `Unsupported` means this target does not offer it. `Unknown` means the evidence could not establish the result. Only `Confirmed` satisfies a strict check. |
| `Reach`     | `Thread` covers the calling thread and threads it starts afterwards. `Process` covers every thread. Interpret scope as a guarantee only for a confirmed result.                                                                                                                                                                                                           |
| `Measure`   | `protection: Protection`, `outcome: Outcome`, `reach: Reach`, `evidence: &'static str`. Use the typed fields for decisions and the evidence text when displaying the result.                                                                                                                                                                                              |
| `Missing`   | `missing: Vec<Protection>` lists the unmet requirements once each in `Protection::ALL` order. `isolation: Isolation` retains the full report for inspection.                                                                                                                                                                                                              |

## Inspect open channels

`open_channels() -> std::io::Result<OpenChannels>` lists file descriptors visible to the calling thread on Unix. They can include channels opened before isolation. Another thread sharing the table can change it during or after inspection. Windows and WebAssembly return `io::ErrorKind::Unsupported`.

| Type           | Public fields and values                                                                                                                                                                                                 |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `OpenChannels` | `channels: Vec<Channel>` sorted by descriptor number, including open standard streams. `complete: bool` is false if some entries could not be listed or examined. In that case even an empty list is inconclusive.       |
| `Channel`      | `descriptor: i32`, `kind: ChannelKind`, `writable: Option<bool>`. `Some(true)` means open for writing, `Some(false)` means the descriptor was not opened for writing, and `None` means the mode could not be determined. |
| `ChannelKind`  | `Socket`, `File`, `Pipe` (including FIFOs), `Terminal`, `Device`, `Directory`, `Other` or `Unknown`. A denied terminal ioctl can make a terminal appear as `Device`.                                                     |

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

| Signature                                                                                                            | Contract                                                                                                                                                                                                                                                                                                                          |
| -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `serve(most: usize, answer: impl FnMut(&[u8]) -> Secret) -> bool`                                                    | Handles requests up to `most` bytes. The handler borrows each request for one call and returns an owned reply. Returns `true` for a recognized worker, including a failed worker startup. Returns `false` outside worker mode or if that role has already been claimed.                                                           |
| `Worker::start(options: Options, required: &[Protection]) -> Result<Worker, WorkerError>`                            | Starts a worker without terminal access. An empty required list still requires a clean start and whole-process isolation.                                                                                                                                                                                                         |
| `Worker::start_within(options: Options, required: &[Protection], deadline: Duration) -> Result<Worker, WorkerError>` | As `start`, with a deadline for the launch, the connection and the startup report. When it passes the start fails with `WorkerError::Start` of kind `TimedOut` and the worker is given up, as for `call_within`.                                                                                                                  |
| `Worker::start_on_terminal(options: Options, required: &[Protection]) -> Result<Worker, WorkerError>`                | Linux/macOS. The worker's standard error is this program's terminal, opened anew for reading and writing, or `/dev/null` when no standard stream is a terminal. The worker has no controlling terminal: it cannot type into the terminal (`TIOCSTI`), and `/dev/tty` does not open. Standard input and output carry the protocol. |
| `isolation(&self) -> Isolation`                                                                                      | Returns the worker’s startup report.                                                                                                                                                                                                                                                                                              |
| `call(&mut self, request: &[u8], most: usize) -> std::io::Result<Secret>`                                            | Sends one request and reads one response, with `most` as the maximum **reply** size. Both limits are bytes.                                                                                                                                                                                                                       |
| `call_within(&mut self, request: &[u8], most: usize, deadline: Duration) -> std::io::Result<Secret>`                 | As `call`, with a deadline for the whole exchange; an answer that arrives past it fails too. When it passes the call fails with `TimedOut` and the worker is given up: its pipes close, and it is terminated where a stable handle exists (Windows, Linux with a pidfd).                                                          |
| `end(self) -> bool`                                                                                                  | Consumes the worker, closes the transport and reports whether it ended. Dropping it also attempts shutdown if it has not already run.                                                                                                                                                                                             |

`WorkerError::Start(io::Error)` covers launch, transport and startup-protocol errors, including an unsupported mode or target. `WorkerError::Unclean` means the worker failed its startup cleanliness check. `WorkerError::Missing(Missing)` supplies the isolation report and the unmet requirements from the admission check. No application request has been sent in any of these cases.

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

The parent retains its own request bytes. The transport uses best-effort `Secret::zeroed` buffers at the receiving end, and dropping them does not erase kernel pipe buffers. For input that must bypass the parent, the terminal worker can read the terminal on its standard error directly. The application must disable echo, check the setting and restore it afterwards; the parent can save the settings before the start and restore them after the worker ends. The worker can write any bytes to the terminal, control sequences included. Linux Landlock can deny terminal-control operations on a newly opened terminal.

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

`with_cleared_stack<T>(work: impl FnOnce() -> T) -> T` runs `work` in a frame of its own and then overwrites `CLEARED_STACK_BYTES` (128 KiB) of the calling thread's stack below the caller's frame with zeros, through volatile writes. That is where `work` and what it called kept their locals: copies that moves leave behind, and the state of dependencies that never wipe it, such as the blocks and hashes of a password hash. `clear_stack()` does the overwrite alone, for each thread of a pool after the secret work it ran, such as the lanes of an Argon2 computation.

It is best effort: how deep the work wrote is not measured, and the thread needs 128 KiB of free stack. Registers, heap copies and other threads' stacks are left as they are. `run_on_protected_stack` instead runs the work on a thread of its own, whose whole stack it wipes.

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
