# Trusted computing base and implementation-defined behaviour

Status: Phase 0 specification, 2026-10-26; Phase 3 components added 2026-10-27. Required by the ratification amendments "State the TCB explicitly and fail closed" and "Implementation-defined behaviour" (spec section 5). Every E claim in the ledger names the parts of this list it rests on, in its `tcb_assumption` column. A bug in any of them is outside every E claim.

## 1. What is trusted

| Component | Trusted to | E claims that rest on it |
| --- | --- | --- |
| rustc front end (parser, type checker, borrow checker) and LLVM | Reject programs the language forbids; compile the rest without introducing unsoundness | All `language` claims; the ownership claims |
| Rust `std` (safe API) | Be sound: no undefined behaviour reachable from safe code | Ownership claims |
| `cargo-corten` (the checker) | Supply its own flags and lint configuration and override every configuration source the checked repository controls (crate README) | All `checker` claims |
| Clippy | Implement each lint the checker turns on as documented | Claims whose mechanism names a Clippy lint |
| `corten-std` | Implement the DirCap monitor (docs/pathseg.md), the typed sinks' encoders, `Secret<T>`, and the broker protocol correctly. Encoder-backed rows carry `review = required` until an independent review is recorded | Path, sink and broker claims (`prelude_only = yes`) |
| `corten-std`'s dependencies: `rustix` 1.1.5 (Linux syscalls, including `openat2`), `region` 3.0.2 (`mlock`), `zeroize` 1.9.1, `subtle` 2.6.1, `ed25519-compact` 2.6.0 (no default features, no further dependencies) | Be correct; each is a dependency of every application that uses the prelude | Path, secret and manifest claims |
| Linux kernel | Implement `openat2` resolve flags and Landlock (ABI v4) as documented | Path and broker claims; the hermetic build |
| `corten-sandbox` and the `landlock` crate 0.4.7 | Turn each grant into exactly the Landlock rule it names, and apply the ruleset before running the program. Landlock's read grant (`from_read`) includes execute, so every read-only path is also executable | Broker claims; the hermetic build; layer 5 |
| `corten-broker` | Clear the environment, enforce the deadline and quotas, and check IPC frame sizes before allocating. It does not close descriptors: the child gets only those its parent holds without close-on-exec, which a Corten program cannot create but its own parent can leak to it (docs/gates/phase-3.md section 4) | Broker claims |
| `wasmi` 2.0.0 (owner decision 12) | Enforce fuel, the memory limit and the absence of imports, and validate modules (`validate`, `extra-checks` features) | Wasm broker claims |
| `corten-runtime` | Restart and stop children as its policy says; contain a panic to the child's thread | Availability claims that rest on supervision |
| `cargo` (vendor and build) | Vendor exactly the locked sources, and build offline from them | The hermetic build and its provenance |
| Cryptographic provider | Implement the primitives it offers correctly | None yet; cryptography is C |
| Capability-manifest verifier and its signing key | Accept only manifests signed by the deployer's key | Every claim about capabilities handed to `main` |
| Hardware | Execute instructions as specified | All claims; transient execution is C |

**Not trusted, and outside every E claim:**

- Dependencies' own code. Registry and git dependencies are built with `--cap-lints allow`, so the profile does not reach them. Layer 3 (spec section 10) and the dependency policy govern them; until then, a dependency can do anything Rust allows.
- **Dependencies' macros, inside the checked crate.** Measured (docs/gates/phase-1.md): a `macro_rules!` exported by a registry dependency can expand to an `unsafe` block in the checked crate, and rustc does not report `unsafe_code` in external macro expansions. Every E claim that rests on the ban on `unsafe` therefore holds only while no dependency exports a macro (or procedural macro) that can emit `unsafe`; the ledger says so on each such row. Layer 3 (`crates/cargo-corten/src/deps.rs`, Phase 3) now refuses a reachable dependency whose `unsafe`-emitting macro or proc macro the local code mentions; the condition remains for any dependency the operator allowlists.
- Known unsoundness in rustc. Bugs tracked under the `I-unsound` label can produce memory errors in safe code; any E claim fails for a program that exploits one. The bypass hunt records which ones were tried.
- Build scripts and procedural macros run with the build's privileges (crates/cargo-corten/README.md), and so does anything a repository's `[env]` table injects into the compiler process (for example `LD_PRELOAD`). The checker resists configuration that weakens the profile; it does not resist a repository that executes code during the build. `cargo corten build` runs the build inside `corten-sandbox` on Linux (no network, writes only beneath `target/`); **`cargo corten check` does not**, and runs dependency build scripts with the caller's privileges (measured, docs/gates/phase-3.md section 4).

## 2. Fail closed

A target that cannot provide a primitive an operation needs refuses the operation with an error. It never falls back to a weaker one. Today this means:

- DirCap: no `openat2`, no file access (docs/pathseg.md section 2).
- Brokers and hermetic builds: no Landlock ABI v4, no sandboxed process. `corten-sandbox` exits 3, and `cargo corten build` refuses to build off Linux.
- Checker: a toolchain it cannot locate is a usage error (exit 2), not an unchecked build.

## 3. Implementation-defined behaviour, enumerated

Corten has no undefined behaviour in the profile. Behaviour that varies by implementation is listed here and either fixed by the profile or exposed as a typed choice. CWE-758 is C, per the amendment.

| Behaviour | Corten's position |
| --- | --- |
| Integer overflow | Fixed: checked. The checker passes `-C overflow-checks=on` and bans unchecked arithmetic operators (`clippy::arithmetic_side_effects`); `Wrapping<T>` and `Saturating<T>` are explicit types |
| Integer width of `usize`/`isize` | Target pointer width. Conversions to fixed widths go through `TryFrom`; `as` is banned |
| Endianness | Target-defined; byte conversions name it (`to_be_bytes`, `from_le_bytes`), and native-endian conversions are an explicit choice |
| Floating point | IEEE 754 binary32/binary64 with round-to-nearest-even; no implicit fused multiply-add; NaN payload bits are unspecified and must not be relied on |
| Float to integer `as` casts | Banned with `as`; use explicit rounding then `TryFrom` |
| Character and string encoding | `char` is a Unicode scalar value; `str` is UTF-8 |
| `HashMap` iteration order | Unspecified (randomly seeded); code must not depend on it |
| Struct layout | Unspecified for `repr(Rust)`; reinterpretation needs `unsafe`, which is forbidden |
| Operating-system error codes | Surfaced as `std::io::ErrorKind`; raw codes are platform-specific and must not drive security decisions |
| Panic strategy | `unwind`, so the supervision tree (Phase 3) can contain a failed component |
| Thread scheduling and timing | Unspecified; concurrency correctness beyond data races is C |
