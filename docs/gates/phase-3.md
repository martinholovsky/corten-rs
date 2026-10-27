# Phase 3 gate: runtime and isolation

Date: 2026-10-27. Toolchain: Rust 1.99.1. Platforms: macOS (development) and Linux (podman `rust:1.99.1-slim-bookworm`; CI on `ubuntu-24.04`). Gate, from spec section 9: "a panic in one component does not stop the service; a broker cannot exceed its declared capabilities."

**Result: the gate's two tests pass on Linux; one Phase 3 item is not built.** A panicking child is restarted while its sibling keeps working. A brokered program is refused every read, write and TCP connection its grant does not name, receives no descriptor (the sandbox refuses to start while one without close-on-exec is open), and is stopped at its deadline and quotas. A hostile dependency build script is refused the network and writes outside `target/` under both `cargo corten build` and `cargo corten check`. Not built: mandatory resource budgets on every parse, decode and allocate entry point. The confinement is Linux only (Landlock): on other platforms `cargo corten build` refuses to build, `check` runs unconfined with a warning, and the process broker has no sandbox to run.

## 1. What Phase 3 built

| Spec item | What exists | Where |
| --- | --- | --- |
| Supervision tree that isolates and restarts a panicked component | `Supervisor`, `ChildSpec`, `Restart` (`Permanent`, `Transient`, `Temporary`), a restart-intensity limit, cooperative `Shutdown`. Each attempt runs on its own thread; a panic is seen through the join result, without `catch_unwind` | `crates/corten-runtime` |
| Process broker with quotas and deadlines | Runs a `corten_std::process::ProcessInvocation` under `corten-sandbox` with a deadline, input and output quotas and a cleared environment. It does not close descriptors (section 4) | `crates/corten-broker/src/process.rs` |
| Wasm broker | `wasmi` 2.0.0 (owner decision 12) with no imports, fuel, a memory limit and an output limit, on a 32 MiB-stack thread | `crates/corten-broker/src/wasm.rs` |
| Schema-checked IPC | Length-prefixed frames; the per-type size limit is checked before allocation; the decoder must consume the whole frame | `crates/corten-broker/src/ipc.rs` |
| Linux sandbox (layer 5) | `corten-sandbox`: Landlock ABI v4 as a hard requirement (exit 3 where the kernel cannot enforce it); `--ro`, `--rw`, `--exec`, `--system`, `--allow-net`; manifest mode turns a signed capability manifest into the rules. It refuses to start (exit 3) while a descriptor above 2 lacks close-on-exec (owner decision, 2026-10-27): the program would inherit it past Landlock, and closing a descriptor the process does not own needs `unsafe`. `scripts/close-leaked-fds.sh` closes such descriptors for a leaky parent (the GitHub runner) | `crates/corten-sandbox` |
| `cargo-corten`: hermetic builds, sandboxed proc macros, SBOM, provenance | `cargo corten build`: the profile and the dependency policy first, then `cargo vendor` outside the sandbox, then `cargo build --release --locked --offline` inside `corten-sandbox` with a private `CARGO_HOME` and temp directory under `target/`. Build scripts and proc macros run inside the sandbox. `cargo corten check` takes the same path on Linux (owner decision, 2026-10-27), vendoring without `--locked` so it may still write `Cargo.lock` as plain `cargo check` does; local path dependencies outside the workspace, and the `Cargo.toml` files above them, are granted read-only. `--sbom` writes CycloneDX 1.5; `--provenance` writes an unsigned in-toto v1 statement with a SLSA v1 predicate (artifact SHA-256 digests, `Cargo.lock` digest, `rustc -vV`, profile flags, whether the build was sandboxed) | `crates/cargo-corten/src/main.rs`, `provenance.rs`, `sha256.rs` |
| Layer 3 dependency policy | Reachable dependencies, `unsafe` exported through `macro_rules!` and proc macros mentioned by local code, a ban list (backtracking regex engines, `libxml`), fail closed on scan limits, operator allowlist only | `crates/cargo-corten/src/deps.rs` |
| Layer 4 | A composite GitHub Action (`action.yml`) that builds the checker from its own lockfile and runs `cargo corten check` or `build`; inputs reach the shell through the environment | `action.yml` |
| Mandatory resource budgets on every parse, decode and allocate entry point | **Not built.** The brokers, the IPC decoder and the checker's JSON parser are bounded; `corten-std` has no general budget type | |

What the build sandbox grants: the system directories, execute on the toolchain root, read-only on the workspace, the checker's configuration directory, `/proc` and `/dev/urandom`, read-write on `/dev/null` and `target/`. No network. Landlock's read grant includes execute (the `landlock` crate's `from_read`), so a read-only path is also executable; this is recorded in [`docs/tcb.md`](../tcb.md).

## 2. Gate tests

All on Linux, in the container; each confinement test first shows the action succeeds without the sandbox (the control).

| Test | Result |
| --- | --- |
| `corten-runtime`: a panicking child is restarted while its sibling keeps working; the restart limit stops everything; a `Temporary` child is not restarted; the panic payload is reported | 4 of 4 pass |
| `corten-sandbox/tests/broker.rs`: reading and writing outside the grant, TCP connect, the deadline, the output quota, the input quota, no descriptor reaching the child, a descriptor without close-on-exec refused (exit 3, with a control), a missing granted path (exit 3), manifest mode granting exactly the manifest | 10 of 10 pass. With Landlock's `apply` replaced by a no-op, 4 fail; with the descriptor check removed, the refusal test fails (both mutation-checked) |
| `cargo-corten/tests/check.rs`: `check_confines_dependency_build_scripts` (a dependency build script writing outside the workspace; control under plain `cargo check`) and the 19 earlier tests, now run sandboxed | 20 of 20 pass. Unsandboxing `check` fails the new test; dropping the path-dependency grants fails `local_path_dependency_outside_the_workspace_is_linted`; removing the `RUSTC_WRAPPER` or `RUSTC_WORKSPACE_WRAPPER` override fails its test under the sandbox (all mutation-checked) |
| `corten-broker/tests/wasm.rs`: echo, a module with any import refused, fuel, memory limit, output limit, garbage | 6 of 6 pass, debug and release. The memory-limit test asserts the limit's trap with fuel set high, and has a roomy-limit control, after an earlier version passed on fuel exhaustion instead |
| `scripts/hermetic-smoke.sh`: a benign crate builds and its provenance digest equals `sha256sum` of the binary; a dependency's build script that opens a TCP connection fails; one that writes outside `target/` fails and the file is not created | 3 of 3 pass. Each hostile case first shows plain `cargo build` lets the build script do it |
| Whole workspace, `cargo test --workspace --all-features --locked` on Linux | 141 passed, 0 failed |

The smoke test runs in CI after the corpus.

## 3. Corpus result

| Measure | Phase 3 (5 cases) | All cases (174) |
| --- | ---: | ---: |
| Detection: every bad program rejected for the expected reason | 1 of 5 | 161 of 174 |
| False rejection | **0 of 5** | 0 of 174 |
| Controls failed | 0 | 0 |
| Broken cases | 0 | 0 |
| Ledger rows verified | 1 new (CWE-403) | 136 of 175 |

From [`corpus-report.md`](corpus-report.md) and `corten-ledger totals`.

- **CWE-403** (descriptor leak): `dup` through FFI and `std::process::Command` are both refused by the profile; the good program opens through `DirCap`, which sets close-on-exec. Verified: the claim is about the program's own descriptors, which it cannot create without close-on-exec. Descriptors its parent leaked into it are the gap in section 4.
- **CWE-1333, 611, 776, 827**: the named crates (`fancy-regex`, `libxml`) are refused by the ban list. Each case also carries a `bad-unlisted.rs` variant: the same engine under a name the list does not know. A name-based ban cannot see it, so these rows stay "not detected" and unverified. Closing them needs either an allowlist of permitted parsers or a property of the code that can be checked, not a longer list.

## 4. Known gaps

| Gap | Measured | Consequence |
| --- | --- | --- |
| No sandbox off Linux | `find_sandbox` refuses off Linux ("refusing to build unconfined") | `cargo corten build` works on Linux only; `check` runs off Linux unconfined, with a warning that build scripts and proc macros run with the caller's privileges |
| A leaky parent cannot run the sandbox | By design (fail closed) | Wrap the call in `scripts/close-leaked-fds.sh`; CI and `action.yml` do |
| A sandboxed check vendors every dependency first | The corpus took 242 s in the container with it | Slower first checks; the vendor step is the only one with network access |
| Resource budgets | Not built | Parsers and decoders in application code are not budgeted by construction |
| The provenance statement is unsigned | By design: signing is layer 4's job | A consumer must get the statement from a signed attestation, not from the file |
| Ban-list rows | Above | CWE-1333, 611, 776, 827 unverified |

## 5. Defects found during Phase 3

| Defect | Found by | Fixed |
| --- | --- | --- |
| The first dependency policy refused any crate exporting an `unsafe` macro: 75 of 169 corpus programs falsely rejected (`bitflags`, `rustix`) | The corpus false-rejection rate | Policy redesigned around reachability and local mentions: 0 of 169 |
| The proc-macro test passed because the local scan read `vendor/` | Reading why it passed | Local packages scan only their target source directories; the test has a genuine invocation, an unused case and a control |
| `wasmi`'s tail-call dispatch overflowed the stack in debug builds | The Wasm tests | `portable-dispatch` and a 32 MiB thread |
| The sandboxed build failed with `EACCES`: cargo writes `CARGO_HOME` locks and reads `/dev/urandom` and `/proc` | The smoke test | Vendor first; private `CARGO_HOME`; those grants |
| `cargo vendor` ignored the repository's source replacement, so a build that plain cargo could do failed to vendor | The smoke test | `--respect-source-config` |
| Linux-only Clippy findings in the broker tests, invisible on macOS | Clippy in the container | Fixed; Linux Clippy is now part of the local check (AGENTS.md) |
| `cargo corten check` ran dependency build scripts on the host: a build script wrote a file outside the workspace and the check exited 0 | A measurement after the build sandbox worked | `check` runs in the sandbox on Linux (owner decision) |
| Descriptors 142 and 145, leaked into the test process by the GitHub runner without close-on-exec, reached the sandboxed child (CI run 40425104715); Landlock does not restrict a descriptor that is already open | CI; the container had none | The sandbox refuses to start while one is open (owner decision); CI and the action close them first |
| The first sandboxed check could not read path dependencies outside the workspace: 77 of 174 corpus programs falsely rejected (`corten-std`) | The corpus false-rejection gate | Read-only grants for local packages and the `Cargo.toml` files above them: 0 of 174 |
| The hostile-tool marker sat in the read-only workspace, so under the sandbox it could no longer show a tool had run | Mutation check of the wrapper tests | The marker lives in the target directory |
