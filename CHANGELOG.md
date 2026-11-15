# Changelog

## Unreleased

First draft; the interface is not frozen.

- `Secret`, `WorkArea`, `Isolation::enter` and `write_secret`, moved from the identical copies in `mhfe_core` and `stego-core`, so that each protection is written and fixed once. `Secret::zeroed` and `Secret::as_mut_bytes` are public, and `WorkArea` is the work area a computation such as Argon2id maps.
- A child process: `Secret::is_out_of_children` and `WorkArea::is_out_of_children` report whether the system confirmed that a child gets none of the bytes (`MADV_WIPEONFORK`, `MADV_DONTFORK`, `minherit`); the copies made these calls and dropped their answers.
- Linux secret memory is opened with `O_CLOEXEC`, so that a program another thread starts in the meantime does not get its descriptor.
- `Isolation::enter` installs its seccomp filter and its Landlock layer once per thread: a further call no longer adds a layer each time and uses up the kernel's limits. The filter is recognised by an answer only it gives, so that a filter the system or a container installed, as every Android app runs under, does not keep this crate's out.
- Landlock is built with the `landlock` crate of the Landlock project instead of hand-written system calls. It asks for the rights of Landlock's ABI 9 (Linux 7.1) and leaves out on an older kernel those it does not know.
- Landlock also refuses a connection to an abstract UNIX socket made outside the layer (from Linux 6.12) and to a UNIX socket by its path (from Linux 7.1), which a socket opened before could make as it could make a TCP connection.
- `Isolation::enter` on Linux also refuses what a probe of the channels found open: System V IPC, POSIX message queues and the keyring, which other programs of the user reach by key or name; `connect`, `bind`, `listen`, `accept`, `sendmmsg` and `sendto` with an address through sockets opened before; `execve`; `process_vm_readv`, `userfaultfd`, `bpf`, `perf_event_open` and the newer mount calls; and the `prctl` options that would make the process readable again. Landlock refuses signals to processes outside it (Linux 6.12), and a process of one thread gets an IPC namespace of its own.
- Speculative store bypass and indirect branch speculation are disabled for good on Linux and Android (`Isolation::speculation_limited`), and side-channel isolation is set on Windows.
- A filter or Landlock layer the system refused is no longer recorded as installed: the next call tries again.
- The answer of `Isolation::enter` no longer overstates: `no_memory_reading` is false under a debugger attached before (Linux, Windows), `no_file_changes` is false on Windows and on Linux without the filter, and `no_core_dumps` is false on Windows.
- Windows: DLLs load only from the program's folder and System32; extension points, remote and low-integrity images and child processes are refused; a job refuses writing the clipboard, global atoms and other processes' windows.
- macOS: the sandbox refuses everything but what a secret command needs, by least privilege; it has yet to run on macOS.
- Every buffer lies between guard pages, and Linux marks anonymous secret pages unmergeable.
- `Secret::locked` and `WorkArea::locked` refuse pages the system did not lock, before a secret is put in them; `ClosedSecret` keeps its pages closed between uses.
- `Options` turns on what may keep a usual program from working, off by default: refusing file locks and `sendmsg` (Linux, Android), no new executable code and only DLLs signed by Microsoft (Windows), each read back in `Isolation`. `Isolation::enter_requiring` and `Isolation::require` stop before a secret when a required `Protection` is missing.
- `Worker` and `serve`: the secret work in a process of its own, which isolates itself before it reads anything and gets a request only once its parent has checked the protections it requires; on Windows in an AppContainer without capabilities.
- `Options::signals_to_self_only` and `Options::lock_all_memory`; `open_channels` lists what is still open after isolation; `Isolation::measures` gives each protection's reach and proof; `run_on_protected_stack` runs secret work on a thread whose stack is protected and wiped.
- `SecretLine` and `Keystroke`: a password typed in a window, collected one key at a time in protected pages.
- Windows: the working set is read and set again as one step, so that threads that make pages at once no longer lose a change and every later drop gives back only what was taken.
- macOS: the probe of file writes makes only a new file and removes only what it made; the copies could truncate a file or the target of a link at a predictable path.
