# AUD-001 Linux report diagnostic

This diagnostic belongs to the review of `60adba5b2f2d144ccdd61cb4829e8e5abc9bc1ca`. It allocates a zero-filled public sample, identifies its mapping using procfs, drops the sample, and compares the reported process lock across two ordinary calls. It reads the OS lock counter. Its output contains flags, a backend label and a size. It needs a disposable Linux process, mounted procfs, the pinned Rust toolchain and the crate's locked dependencies. The original run used the workspace toolchain and resource wrapper.

From the repository root in Bash, set the workspace toolchain environment as described in AGENTS.md and use an empty build directory.

```bash
build_dir=$(mktemp -d)
run-capped --mem 1500M --time 10m -- env CARGO_TARGET_DIR="$build_dir" cargo build --lib --locked --offline
rlibs=("$build_dir"/debug/deps/libsecret_protection_core-*.rlib)
run-capped --mem 1500M --time 5m -- rustc --edition 2024 \
  -L "dependency=$build_dir/debug/deps" --extern "secret_protection_core=${rlibs[0]}" \
  docs/audits/AUD-001-harnesses/report_state.rs -o "$build_dir/report-state"
run-capped --mem 256M --time 2m -- "$build_dir/report-state"
```

The backend and lock counter depend on kernel support and process limits. On the audit host the first call reported a successful lock, the second reported false, both descriptions said `mlockall accepted`, and `VmLck` still reported 3348 kB. The diagnostic does not access another process.
