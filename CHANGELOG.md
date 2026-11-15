# Changelog

## Unreleased

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
