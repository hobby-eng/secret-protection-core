# AUD-006 WebAssembly runtime checks

These four checks exercise the public heap fallback of secret-protection-core at commit `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f`. They use four public ASCII bytes and a zeroed work area. They cover appending and truncating a secret, optional page sealing, fallible work-area allocation, and unavailable isolation measures.

From the repository root, use the pinned Rust toolchain, the installed wasm32-unknown-unknown target, an empty target directory and Node.js. On the workspace laptop run the build commands under run-capped. No browser or network is required.

```bash
set -eu
: "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to an empty audit build directory}"
h=docs/audits/AUD-006-harnesses
cargo build --lib --locked --offline --target wasm32-unknown-unknown
d="$CARGO_TARGET_DIR/wasm32-unknown-unknown/debug"
rustc --edition=2024 --crate-type=cdylib --target wasm32-unknown-unknown "$h/fallback.rs" \
  -L "dependency=$d/deps" --extern "secret_protection_core=$d/libsecret_protection_core.rlib" \
  -o "$CARGO_TARGET_DIR/fallback.wasm"
node "$h/fallback.mjs" "$CARGO_TARGET_DIR/fallback.wasm"
```

The runner prints one passed line per check and exits with zero. A failed Rust assertion traps and fails the Node process. This is a run of the compiled fallback in V8. Browser integrations, browser APIs and native operating-system policies are outside its scope.
