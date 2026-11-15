# Changelog

## Unreleased

First draft; the interface is not frozen.

- `Secret`, `WorkArea`, `Isolation::enter` and `write_secret`, moved from the identical copies in `mhfe_core` and `stego-core`, so that each protection is written and fixed once. `Secret::zeroed` and `Secret::as_mut_bytes` are public, and `WorkArea` is the work area a computation such as Argon2id maps.
- A child process: `Secret::is_out_of_children` and `WorkArea::is_out_of_children` report whether the system confirmed that a child gets none of the bytes (`MADV_WIPEONFORK`, `MADV_DONTFORK`, `minherit`); the copies made these calls and dropped their answers.
- Linux secret memory is opened with `O_CLOEXEC`, so that a program another thread starts in the meantime does not get its descriptor.
- `Isolation::enter` installs its seccomp filter and its Landlock layer once per thread: a further call no longer adds a layer each time and uses up the kernel's limits. The filter is recognised by an answer only it gives, so that a filter the system or a container installed, as every Android app runs under, does not keep this crate's out.
- Landlock is built with the `landlock` crate of the Landlock project instead of hand-written system calls. It asks for the rights of Landlock's ABI 9 (Linux 7.1) and leaves out on an older kernel those it does not know.
- Landlock also refuses a connection to an abstract UNIX socket made outside the layer (from Linux 6.12) and to a UNIX socket by its path (from Linux 7.1), which a socket opened before could make as it could make a TCP connection.
- Windows: the working set is read and set again as one step, so that threads that make pages at once no longer lose a change and every later drop gives back only what was taken.
- macOS: the probe of file writes makes only a new file and removes only what it made; the copies could truncate a file or the target of a link at a predictable path.
