# AUD-012 linked-library descriptor harness

This harness belongs to AUD-012 and reviews commit `2747028f4452c3e36f2a500eabdbc795010bf295`. It uses only `/dev/null` and synthetic processes, never real secrets.

## What it checks

A linked library's constructor closes the descriptor inherited from the synthetic parent and opens its own `/dev/null`, reusing the same number. The crate's worker initializer then runs. The descriptor now owned by the library must remain open; closing it would contradict the documented startup boundary.

The executable and library are separate crates, so the system runs the shared library's initializer before the executable's. The child verifies both that reuse occurred and that the descriptor remains open.

## Prerequisites and command

Linux, Rust 1.99.1 and Cargo. Use the workspace toolchain homes and a separate target directory. From this folder:

```sh
export CARGO_TARGET_DIR=/path/to/a-separate-target
cargo build --quiet --locked --offline --package secret-protection-core-aud-012-library
RUSTFLAGS="-L $CARGO_TARGET_DIR/debug" \
  LD_LIBRARY_PATH="$CARGO_TARGET_DIR/debug${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  cargo run --quiet --locked --offline --package secret-protection-core-aud-012-program
```

Expected secure result is exit 0 with `PASS: worker startup preserved the descriptor reused by the linked library`. A nonzero exit or `FAIL` means the worker initializer closed the library's reused descriptor.
