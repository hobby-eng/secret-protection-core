# Third-party notices

The versions below come from the library's [Cargo.lock](Cargo.lock). The fuzz targets have a [separate lockfile](https://github.com/hobby-eng/secret-protection-core/blob/main/fuzz/Cargo.lock) for development tools, in the repository only: the published package leaves the fuzz targets out.

## Library dependencies

- **zeroize 1.9.2** clears secret bytes using writes the compiler must retain. RustCrypto project developers, MIT OR Apache-2.0.
- **libc 0.2.191** supplies the Unix C types, constants and OS function declarations. Rust project developers, MIT OR Apache-2.0.
- **windows-sys 0.61.2** supplies Windows API declarations. **windows-link 0.2.1** links them. Both are by Microsoft, MIT OR Apache-2.0.
- **landlock 0.4.8** builds the Linux Landlock layer in `Isolation::enter`. It describes the rights supported by each ABI and applies the subset available on older kernels. Developed by the Landlock project, copyright Mickaël Salaün, MIT OR Apache-2.0.
- Landlock uses **enumflags2 0.7.12**, by Maik Klein and Maja Kądziołka, and **thiserror 2.0.21**, by David Tolnay. Both use MIT OR Apache-2.0.

## Build dependencies

- **enumflags2_derive 0.7.12** provides the macros for enumflags2. Maik Klein and Maja Kądziołka, MIT OR Apache-2.0.
- **thiserror-impl 2.0.21** provides the macros for thiserror. David Tolnay, MIT OR Apache-2.0.
- **proc-macro2 1.0.107** supplies token streams for procedural macros. David Tolnay and Alex Crichton, MIT OR Apache-2.0.
- **quote 1.0.47** and **syn 2.0.119 and 3.0.10** generate and parse Rust tokens for those macros. David Tolnay, MIT OR Apache-2.0.
- **unicode-ident 1.0.27** supplies Unicode identifier tables. David Tolnay, (MIT OR Apache-2.0) AND Unicode-3.0.
