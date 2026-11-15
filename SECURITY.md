# Security

This crate helps an application keep passwords and keys in memory for the time it needs them. The operating system decides which protections it can grant. A program that depends on a protection should check it before reading the first secret. [API description](docs/API.md)

## Memory and copies

Use `Secret::locked` or `WorkArea::locked` when the contents must stay out of swap. They return an error if the OS refuses the lock. Dump exclusion and protection across a fork are separate properties. Check them on the allocation that will hold the data.

On normal destruction in the owning process, the library wipes its buffers. A fatal signal, an abort or `std::process::exit` can skip that wipe. Copies made by the caller, an input widget, the clipboard, a terminal recorder or a virtual-machine snapshot have their own lifetimes. In WebAssembly, the library can wipe the buffer it owns. Paging, crash reports and copies in the host remain under the host's control.

A continuing Unix child must discard any references it borrowed before `fork`. An inherited buffer owner detects the fork on a fresh byte access and aborts. A previously borrowed slice has no such check. Keep the process from forking while any thread is running on a protected stack. [Memory and fork behavior](docs/TECHNICAL.md#a-secrets-pages)

## Process and worker boundaries

`Isolation::measures()` reports what the crate could confirm when isolation was entered, including whether each measure covers one thread or the process. For example, an existing connection can still carry data after the OS refuses new sockets. Standard output can already point to a file or pipe. Inspect open channels on systems that support it. [Platform contracts](docs/TECHNICAL.md)

A worker trusts its launcher, its executable and the libraries loaded at startup. The parent checks the clean-start report, whole-process isolation and the process-wide protections it requires before sending an application request. On Windows the worker checks its threads' access controls and effective tokens using the lists supplied by the parent. If a standalone process cannot see its own thread list, it cannot confirm a protection that depends on that list. The report does not revoke a handle another process already has.

Privileged debuggers, a compromised OS and malicious code already running inside the application are outside this boundary. A trusted GUI still sees the keystrokes it forwards. A Unix worker that reads directly from a terminal can keep the input out of the parent, provided the application also manages terminal echo. [Worker startup and input](docs/TECHNICAL.md#the-worker-process)

## Reporting a problem

The repository's issue tracker is public. Include the source revision, operating system, the protection or API involved, and the expected and observed result. Use invented input. If a dump, log or screenshot contains a real secret, leave it out of the report. [GitHub Issues](https://github.com/hobby-eng/secret-protection-core/issues)
