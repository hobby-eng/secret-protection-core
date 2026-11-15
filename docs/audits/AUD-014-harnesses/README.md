# Public API checks for AUD-014

These checks use the public API of secret-protection-core at commit `fb2a6d345caf8eb58097f013f12e43985402150f`. The only inputs are Unicode scalar values, seven literal invalid frames and the public bytes `ok`. No wallet or user data is needed.

Run the following commands from the crate root on Linux with the pinned Rust toolchain. On the workspace laptop, start each build and test command with `run-capped --`. The paths below assume Cargo's default target directory.

```sh
cargo build --release --lib --locked --offline
rustc --edition=2024 -C opt-level=2 docs/audits/AUD-014-harnesses/api.rs \
  -L dependency=target/release/deps \
  --extern secret_protection_core=target/release/libsecret_protection_core.rlib \
  -o target/aud-014-api
target/aud-014-api
```

The harness compares every valid scalar's frame with Rust's UTF-8 representation, applies it to a fixed-size secret line, checks the character count and removes it. It also checks rejection of malformed frames and preservation of contents after a capacity error. Success exits with status zero and prints `1112064 Unicode scalars, 7 invalid frames and one capacity boundary passed`. Any failed assertion gives a nonzero exit.
