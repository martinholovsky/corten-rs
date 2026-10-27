# Phase 3b trial: Corten's own lints on a pinned nightly

Date: 2026-10-27. Driver toolchain: `nightly-2026-10-26`, rustc 1.101.0-nightly (76456a688 2026-10-25), pinned in `crates/corten-lints/rust-toolchain.toml`. Checker toolchain: Rust 1.99.1. Platform: Linux (podman `rust:1.99.1-slim-bookworm`).

Question 10 (spec section 8) asked whether the checker may depend on a pinned nightly for lints that stable Clippy cannot express. The owner chose to try it and decide on the results. This is the trial. **The decision is still open:** the lints run only where `corten-driver` is installed, CI's corpus runs without it, and no ledger row was marked verified on its strength.

## 1. What was built

`crates/corten-lints` builds `corten-driver`: rustc with seven lints registered, outside the stable workspace and with no dependencies. It is a rustc driver like `clippy-driver`, not dylint: one binary, nothing downloaded, and it plugs into the checker as the compiler for a second `cargo check` pass. `build.rs` records the nightly's library directory as an rpath, so the binary starts without `LD_LIBRARY_PATH` and is tied to that toolchain installation.

`cargo corten check` runs the second pass after the first passes, when it finds the driver (`CORTEN_DRIVER`, or beside `cargo-corten`): `RUSTC` is the driver, the flags are only `-F corten_*`, the target directory is `target/corten-lints`, and on Linux it runs in the sandbox like the first pass, with the driver and its sysroot granted read-only. `RUSTC_BOOTSTRAP=-1` stays pinned, so the nightly compiler refuses `#![feature]` in the checked code as a stable one does. Without the driver the checker prints a note naming the lints that did not run and passes.

| Lint | Row | Rule |
| --- | --- | --- |
| `corten_must_use_return` | CWE-252 | `f();` or `let _ = f();` where `f` returns anything but `()` or `!`. Exempt: a method returning a reference to its own receiver's type (a builder, `cmd.arg(x);`), and code from external macros |
| `corten_labelled_params` | CWE-683 | An exported function with two or more parameters of the same type (regions erased). Exempt: private functions, trait implementations, closures |
| `corten_pub_interior_mut_static` | CWE-493, 500, 607 | A `pub` static whose type is not `Freeze` |
| `corten_unsafe_from_macro` | The Phase 1 bypass | An `unsafe` block, `unsafe fn` or `unsafe impl` whose span comes from a macro defined outside `std`, `core` and `alloc` |
| `corten_direct_template` | The Phase 2 gap (CWE-838) | A call to `corten_std::*::from_template` not expanded from a `corten-std` macro |
| `corten_blocking_in_async` | CWE-1322 | A call inside an `async` body to a listed std blocking primitive (`thread::sleep`, `Mutex::lock`, `JoinHandle::join`, channel `recv`, `fs`, `net`, `process`, and others), to `corten_std::fs`, or to a local function that reaches one (fixpoint over local calls). Calls into other crates are not followed; closures inside the async body are separate bodies and not followed |
| `corten_rc_cycle` | CWE-1091 | A type with a destructor that can reach itself through both an `Rc`/`Arc` and an interior-mutability cell (`Cell`, `RefCell`, `Mutex`, `RwLock`, `OnceCell`, `OnceLock`, `UnsafeCell`). `Weak` edges do not count. Decided on types: a type that only ever forms trees is still reported |

**Why the dependency-macro bypass existed, read in the compiler source.** `rustc_middle/src/lint.rs` (line 473 in this nightly) drops a lint whose span is in an external macro unless the lint is declared `report_in_external_macro`; `unsafe_code` is not. A custom lint can declare it, and `corten_unsafe_from_macro` does.

## 2. Tests

| Test | Result |
| --- | --- |
| `crates/corten-lints/tests/ui.rs`: six fixtures, each with the lint's must-fire cases, its exemptions and an exact error count; a dependency built as a real rlib whose macro expands to `unsafe` (control: rustc's `-F unsafe_code` accepts it); a stand-in `corten_std` whose own macro may call `from_template` and a direct call that may not | 3 of 3 pass. Removing any one of the seven lint passes fails a test (7 of 7 mutations caught) |
| `cargo-corten/tests/check.rs` `lint_pass_refuses_unsafe_from_an_allowed_dependency_macro`: an allowlisted dependency's macro expanding to `unsafe`, through `cargo corten check` in the sandbox. Control: without the driver it passes | Passes with the driver; with `CORTEN_REQUIRE_DRIVER=1` and no driver it fails, as asked. The CI `lint driver (nightly)` job runs it that way |

## 3. Corpus

Run in the container, once without the driver (what CI runs) and once with it beside the checker.

| Measure | Without the driver | With the driver |
| --- | ---: | ---: |
| Detection | 161 of 174 | **168 of 174** |
| False rejection | 0 of 174 | **1 of 174** |
| Controls failed, broken cases | 0, 0 | 0, 0 |

Rows that pass only with the driver: CWE-252, 493, 500, 607, 1091, 1322, and CWE-838's direct-call variant (the row still waits for the encoder review). Still not detected with it: CWE-683 (`bad-private.rs`, below), CWE-396 (`thread::join` as a catch-all; no lint was attempted), and the four ban-list rows.

The one false rejection is CWE-581's matched good program, `m.insert(Key(1), "one");`, which discards the `Option` that `HashMap::insert` returns. The spec's rule, every non-unit return is must-use (ratification amendment "Must-use scope"), rejects it as written.

**The labelled-parameter rule.** Requiring labels on every function falsely rejected 4 of 174 good programs (`fn f(a: u32, b: u32)` helpers in CWE-95, 628, 685, 686). The spec asks for labels on public functions only (4.2), and that rule falsely rejects none, but it does not see the swap through a private function, so `corpus/CWE-683/bad-private.rs` records it and CWE-683 stays unverified.

## 4. Real code: this repository

The seven lints as warnings over the workspace's own library and binary code (`cargo check --workspace --lib --bins`; 8,984 lines in the seven crates' `src/`, which also counts in-file test modules the run did not check):

| Lint | Hits |
| --- | ---: |
| `corten_must_use_return` | 19 (11 `Option`, 6 `bool`, 1 `ScopedJoinHandle`, 1 `&mut DirBuilder` through a fully qualified trait call the builder exemption does not see). Before the builder exemption: 55, of which 34 were `&mut Command` |
| `corten_labelled_params` | 5, each a real swap hazard in a public API: `Toolchain::from_env(cargo, rustc)` (two `Option<OsString>`), `lint_command` (three `&Path`), `vendor_command` (two `&Path`), `corten_ledger::set_status` (two `&[&str]`), `corten_broker::wasm::run(module, input)` (two `&[u8]`) |
| The other five | 0 |

`corten-std`, which every corpus case builds under the profile, had to change to pass: `manifest::verify` and `Capabilities::load` take `Signature` and `PublicKey`, `ProcessInvocation::new` takes `Options` and `Operands`, `SetCookie::new` takes `CookieName` and `CookieValue`, and the two `insert` results in `Capabilities::load` are checked. Those were the same swap hazards: options passed as operands is option injection.

## 5. What adopting it costs

- **A nightly in the trusted base.** The driver is rustc's front end from `nightly-2026-10-26` plus 703 lines of driver, lint and build-script code. The stable 1.99.1 compiler still does the first pass; the nightly sees the code only to lint it, and `RUSTC_BOOTSTRAP=-1` holds it to stable's feature gates.
- **Breakage per nightly.** In this one nightly, five rustc internal APIs differed from what the code was first written against (`compiler_entrypoint`, `register_late_lint_pass`, `emit_span_lint` with `DiagDecorator`, `default_field_values` in `declare_lint!`, and the `Unnormalized` wrapper from `instantiate_identity`). Moving the pin means repeating that.
- **Install.** The nightly with `rustc-dev` is a separate toolchain download, and the driver is built against it.
- **The must-use rule as specified** rejects ordinary code like `map.insert(k, v);`: 1 of 174 corpus programs, and 19 sites in about 9,000 lines here.

## 6. The decision this informs

Question 10 stays open for the owner. The options this data supports:

1. **Adopt**: the driver ships with the checker, a missing driver becomes an error, and the six rows are verified on the next `--mark-verified` run.
2. **Adopt without the must-use rule**, or with a narrower one (for example, only `Result`, `Option` and `bool` from functions in the checked crate), trading CWE-252's E claim for less churn.
3. **Do not adopt**: the rows stay unverified until stable Clippy can express them, and the driver stays a trial.
