# AUD-002 reproduction harnesses

These Rust commands belong to AUD-002 and review commit `60adba5b2f2d144ccdd61cb4829e8e5abc9bc1ca`. They use only synthetic processes and bytes, never real secrets. The reviewed crate is used through its public interface; the harness does not change it.

## Prerequisites

- Rust 1.99.1 and Cargo, with the workspace `CARGO_HOME` and `RUSTUP_HOME` on the development machine.
- Linux on x86-64 or AArch64 for `ipc`, `pidfd-signal` and `inherited-fd`; `worker-drop` and `stack-overflow` also apply to the other desktop systems once their runtime checks are available.
- A system that permits user and network namespaces for the IPC check. If the system refuses one, that check reports `SKIP` and is not evidence of a pass.
- Bubblewrap (`bwrap`) for the inherited-descriptor check. It creates a private namespace with a minimal synthetic `/proc`: `self/exe` lets the worker start, while the absent `self/fd` exercises the fallback failure. No host mount or real secret is used.
- The `sleep` executable for the synthetic target of the pidfd check.

## Commands

Run from this folder, through `run-capped` on the development machine:

```sh
cargo run --quiet -- ipc
cargo run --quiet -- pidfd-signal
cargo run --quiet -- worker-drop
cargo run --quiet -- stack-overflow
cargo build
mkdir -p output/fake-proc/self
ln -sfn "$(pwd)/target/debug/secret-protection-core-aud-002" output/fake-proc/self/exe
bwrap --unshare-all --die-with-parent --bind / / \
  --bind "$(pwd)/output/fake-proc" /proc --dev /dev -- \
  "$(pwd)/target/debug/secret-protection-core-aud-002" inherited-fd
```

Expected secure results, each with exit code 0:

- `ipc`: `PASS: network and IPC namespaces differ from their parent`, or an explicit `SKIP` when namespaces are unavailable.
- `pidfd-signal`: `PASS: pidfd_send_signal was refused with EACCES`. A foreign seccomp filter first refuses Landlock, so the check exercises the implementation needed on kernels before 6.12 and on Android instead of letting Landlock hide a filter defect. Signal 0 is used, so no signal is delivered.
- `worker-drop`: `PASS: dropping the worker returned`. The synthetic answer is 1 MiB and the caller allows at most 1 KiB. A three-second watchdog turns a deadlock into exit code 1.
- `stack-overflow`: `PASS: an overflowing stack size returned an error`.
- `inherited-fd`: `PASS: the worker inherited no socket`. A foreign seccomp filter refuses `close_range`; with `self/fd` absent, the worker must stop instead of starting with the inherited socket. If it answers `open`, it also writes one synthetic byte through that socket to demonstrate the live channel.

Any `FAIL` line or nonzero exit code is a failed security or lifecycle check. The audit records the observed failures rather than treating them as expected behavior.
