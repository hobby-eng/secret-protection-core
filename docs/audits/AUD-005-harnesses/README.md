# AUD-005 reproduction harness

This Rust command belongs to AUD-005 and reviews commit `6aa7e56fb39dc21c09ac939020423ec13896b2eb`. It uses only synthetic processes and signal 0, never real secrets or a delivered signal. The crate is exercised through its public API and is not modified.

## Prerequisites

- Linux on x86-64 or AArch64, with user, network and IPC namespaces available.
- Rust 1.99.1 and Cargo, with the workspace `CARGO_HOME`, `RUSTUP_HOME` and a separate `CARGO_TARGET_DIR`.

## Command

Run from this folder through `run-capped` on the development machine:

```sh
cargo run --quiet --locked --offline
```

Expected secure result, with exit code 0:

- The parent enters with `signals_to_self_only`.
- A foreign filter then refuses every later `PR_SET_SECCOMP` upgrade.
- After `fork`, the child requests `signals_to_self_only` plus `refuse_sendmsg`, forcing an upgrade that fails.
- The child must return `Refused` for `SignalsToSelfOnly`: its inherited rule still names the parent. The probe also prints the results of signal 0 to the child and parent, making the actual rule visible.

A `FAIL` line or nonzero exit means the child incorrectly confirmed its parent's signal rule. The command sends no actual signal.
