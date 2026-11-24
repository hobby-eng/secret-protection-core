# Changelog

## Unreleased

- On Windows the worker process and its first thread are created with their restricted access lists. Before, they had the default lists until the worker isolated itself, and another process of the same user could open the worker in that interval.
- `Worker::start_within` and `Worker::call_within` take a deadline. When it passes, the start or call fails with `TimedOut` and the worker is given up, terminated where a stable handle exists (Windows, Linux with a pidfd), so a worker that stops answering no longer blocks its parent for longer than the deadline and the shutdown wait. `start` and `call` keep waiting without a deadline.
- `Isolation::enter_requiring_process_wide` and `Isolation::require_process_wide` require each listed protection, and `WholeProcess`, to cover every thread, the rule a worker is admitted by. `Missing` from them lists every unmet protection.
- A release is built only after the tests on every platform, the dependency audit and a short fuzzing run pass for the tagged commit.
- `THIRD_PARTY_NOTICES.md` names the versions in `Cargo.lock`, which CI now checks. In 0.1.1 it still named zeroize 1.9.1 and landlock 0.4.7.
- Every Unix worker leaves its parent's session, the one on the terminal too, so no worker can type into the shell through a controlling terminal (`TIOCSTI`). `start_on_terminal` now gives the worker this program's terminal, opened anew for reading and writing, as its standard error, or `/dev/null` without one, never a socket or file the parent's standard error points to; `/dev/tty` no longer opens in it. A worker that cannot leave the session is not clean.
- The macOS sandbox writes data only to `/dev/null` and the process's own terminal, without mode or owner changes, allows ioctls only on that terminal and refuses reading the user's other terminals. It used to allow every write and ioctl on every terminal.
- Linux clears the dumpable flag and the core limit before entering the user namespace. Before, another process of the user could open the process's memory in between.
- The Linux filter limits resource limits, scheduling, page placement and robust-list reads to the process itself and refuses `kcmp`, `process_madvise` and `ioprio_set`. `signals_to_self_only` also refuses the `fcntl` owner commands, and `refuse_file_locks` refuses leases.
- Protected stacks on Linux ask for small pages, as secrets do. Linux starts a worker from `/proc/self/exe`.
- A Unix start with a deadline also bounds the wait for the launch. A deadline too far ahead for the clock to hold waits without one, as the documentation now says.
- On macOS a process whose standard streams are not terminals gets no terminal rule at all, `/dev/tty` included, so it cannot type into a controlling terminal.
- A worker reuses one request buffer, wiped after each request, instead of making a new secret for every frame; on Windows a call with a deadline starts one watchdog thread instead of four.
- CI checks that `THIRD_PARTY_NOTICES.md` names exactly the packages of the library's dependency tree with their complete versions; the fuzz workspace pins `libfuzzer-sys` exactly, and a release fuzzes only with the checked-in fuzz lockfile, before and after.
- Linux enters its user namespace only when the cleared dumpable flag reads back. `signals_to_self_only` also refuses `F_SETSIG` and setting `O_ASYNC`, after which a terminal would name its foreground group as the owner by itself; `refuse_file_locks` also refuses delegations (`F_SETDELEG`). Calls on a process accept only 0, the caller, so that a child of `fork` cannot name its parent.
- On Windows a start or call with a deadline goes by the clock: work that ends past the deadline fails, and the launch checks the deadline before and after the calls that cannot be cut short. A Unix launch that finishes after its start gave up is ended through its stable handle.
- The macOS sandbox keeps reads off every terminal device but the process's own.

## 0.1.1 (2026-11-24)

- Dependencies take compatible version ranges instead of exact versions, so a program that also needs a newer libc, zeroize, landlock or windows-sys builds with this crate. `Cargo.lock` keeps the versions the crate is tested with: zeroize 1.9.2 and landlock 0.4.8, the rest unchanged. The public interface is the same as in 0.1.0.
- The package on crates.io is the file the signed GitHub release attests.

## 0.1.0 (2026-11-15)

### Memory and input

- `Secret` holds bytes at a fixed capacity. `Secret::zeroed` and `as_mut_bytes` let an application fill the buffer directly. `WorkArea` provides zero-initialized scratch space for computations such as Argon2id. Both types wipe their storage on normal drop in the owning process.
- `Secret::locked` and `WorkArea::locked` return an error if the allocation cannot be locked. Native buffers have guard pages. On Linux the library requests small, unmergeable anonymous pages for secrets and leaves the work area's page size to the kernel. WebAssembly can return `None` for an allocation that `WorkArea::new` cannot satisfy.
- `ClosedSecret` restricts page access between callbacks. `is_closed()` reports whether closing succeeded. `run_on_protected_stack` checks the requested stack properties before starting the thread and wipes the stack after it exits.
- `SecretLine` collects typed characters in a fixed-capacity buffer. `Keystroke::to_bytes` produces a frame that wipes its bytes on drop. `write_secret` writes directly to standard output after flushing buffered output.

### Forks and process isolation

- Unix allocations remember which process owns them. An inherited owner reports its protection flags as false, skips the parent's mapping on drop and aborts on fresh byte access. `is_out_of_children()` reports whether the OS excluded the contents from a fork. Borrowed slices and active protected stacks have separate [fork requirements](SECURITY.md#memory-and-copies).
- On Linux, kernel secret memory uses a close-on-exec descriptor and coordinates with `fork` while that descriptor is open. If setup happened too late in a multithreaded process, signals cannot be blocked, or the fork gate stays busy for 100 ms, the allocator falls back to anonymous pages.
- Each isolation measure reports its outcome, scope and evidence. `Isolation::enter_requiring` lets an application stop before reading input when a required measure is unconfirmed. `open_channels` lists the open descriptors it could inspect on Unix and indicates whether the list is complete. Windows and WebAssembly return an unsupported error.
- On supported Linux architectures and on supported Android native threads, the syscall filter restricts new sockets, program execution and operations through existing descriptors. Optional rules restrict file locks, `sendmsg` and signals. Linux can also lock process memory, apply Landlock rights through ABI 9, and request user, network and IPC namespaces together. A connected socket may remain usable. Failed filter or Landlock setup can be retried.
- Linux and Android check both supported kinds of speculation. A CPU that needs no mitigation can confirm the measure. When the kernel exposes too little information, the result can be unknown. On Linux, a tracer outside a PID namespace can be invisible. A denied probe alone cannot confirm that the crate installed its own filter.
- On macOS, the library requests debugger protection before entering the sandbox. File and socket probes count as confirmation only with the crate's profile in place. The file probe uses exclusive creation, then tries to unlink the probe path if creation succeeded.
- On Windows, the library reads back the process and thread access controls, token integrity, job limits and supported mitigation policies. Options can restrict dynamic code and require Microsoft-signed images. The default DLL search uses the application directory and System32. Working-set updates are serialized, and a work area reports a successful lock even when its working set did not grow.

### Workers and verification

- `Worker::start` and `serve` run secret operations in a separate process. Unix workers close inherited nonstandard descriptors before the executable starts. Windows workers start in an AppContainer without inheriting handles. The parent and worker authenticate the local pipe connection before exchanging thread lists and the startup report.
- On Windows, a standalone check reports `Unknown` when it needs a thread list the OS withholds. During worker startup the parent supplies fresh lists. The worker can read a live thread's token through the handle it acquired before tightening access. The parent keeps only wait and termination rights on the worker process.
- A failed exchange closes the transport. Linux can terminate a worker through a pidfd acquired at spawn. The Unix fallback uses cooperative shutdown and collects a late exit. `Worker::end` tells the caller whether the worker ended within the shutdown deadline.
- Three fuzz targets cover worker settings, the isolation fields of startup reports and encoded keystrokes. The Linux coverage run includes the integration programs and their worker processes. The tests distinguish a skipped subcase from one that ran. [Coverage](docs/COVERAGE.md) · [Audit history](docs/audits/README.md)
