# Security

This crate helps an application keep passwords and keys in memory for the time it needs them. The operating system decides which protections it can grant. A program that depends on a protection should check it before reading the first secret. [API description](docs/API.md)

## Memory and copies

Use `Secret::locked` or `WorkArea::locked` when the contents must stay out of swap. They return an error if the OS refuses the lock. Dump exclusion and protection across a fork are separate properties. Check them on the allocation that will hold the data.

On Linux the kernel can copy a work area's pages when it joins them into a huge page, and move locked anonymous pages when it compacts memory; it frees the old pages without wiping them. Booting with `init_on_free=1` wipes freed pages, and `vm.compact_unevictable_allowed=0` keeps locked pages in place.

On normal destruction in the owning process, the library wipes its buffers. A fatal signal, an abort or `std::process::exit` can skip that wipe. Copies made by the caller, an input widget, the clipboard, a terminal recorder or a virtual-machine snapshot have their own lifetimes. In WebAssembly, the library can wipe the buffer it owns. Paging, crash reports and copies in the host remain under the host's control.

A continuing Unix child must discard any references it borrowed before `fork`. An inherited buffer owner detects the fork on a fresh byte access and aborts. A previously borrowed slice has no such check. Keep the process from forking while any thread is running on a protected stack. [Memory and fork behavior](docs/TECHNICAL.md#a-secrets-pages)

## Process and worker boundaries

`Isolation::measures()` reports what the crate could confirm when isolation was entered, including whether each measure covers one thread or the process. For example, an existing connection can still carry data after the OS refuses new sockets, and an `io_uring` ring created before isolation keeps running requests. Standard output can already point to a file or pipe. Inspect open channels on systems that support it. [Platform contracts](docs/TECHNICAL.md)

A worker trusts its launcher, its executable and the libraries loaded at startup. Linux starts a worker from the very file the parent runs; on macOS and Windows, a file put in place of the program's file is what later workers run. The parent checks the clean-start report, whole-process isolation and the process-wide protections it requires before sending an application request. On Windows the worker checks its threads' access controls and effective tokens using the lists supplied by the parent. If a standalone process cannot see its own thread list, it cannot confirm a protection that depends on that list. The report does not revoke a handle another process already has.

Privileged debuggers, a compromised OS and malicious code already running inside the application are outside this boundary. A trusted GUI still sees the keystrokes it forwards. A Unix worker that reads directly from a terminal with `read_hidden_line`, which turns the echo off, keeps the input out of the parent, as long as the program stays the foreground job and leaves the terminal alone meanwhile: the worker has no job control. While it lives such a worker can also read other keys typed on the terminal, change its settings and make it send replies that the next reader takes as input. Such a worker has no controlling terminal, so it cannot type into the shell, but it can write any bytes to the terminal, control sequences included. On macOS, a process that isolates itself while it keeps a controlling terminal can still type into it (`TIOCSTI`), which the sandbox cannot refuse on its own, and on Windows a process that keeps a console it may write to can put input into it (`WriteConsoleInput`), where the integrity level and console policy allow: read untrusted input in a worker. A Windows worker is started without a console and inherits no handle. Other local processes can read a process's name and command line, which code running after isolation can change. [Worker startup and input](docs/TECHNICAL.md#the-worker-process)
