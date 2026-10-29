# Changelog

Newest first. Nothing is released yet.

## Unreleased

### Added

- `scripts/applicability-chart.py` generates `docs/assets/cwe-rust-corten.svg` from the applicability table, and CI fails when the SVG is stale (the PNG is still rendered by hand, since it needs the Archivo font). The Corten bar gains a hatched segment for the eliminations Corten claims but its corpus does not yet prove; they still count as writable.
- Per-CWE Rust applicability review (`audit/applicability/`, `docs/rust-applicability.md`): every one of the 944 CWEs answered for Rust with `unsafe`, safe Rust and Corten, with reasoning, and 435 programs re-checked against rustc in CI. Result: 785 writable with `unsafe`, 722 in safe Rust, 641 under Corten's verified eliminations; 67 need constructs Rust lacks and 92 are not code. *Updated 2026-10-28* (transient-execution rows corrected: CWE-1420, 1421 and 1423 can be introduced by software, CWE-1037 cannot): 787, 724 and 643; 67 and 90. Chart: `docs/assets/cwe-rust-corten.svg`.
- CI checks that `docs/rust-comparison.md` is current: it fetches only the baseline commit `scripts/applicability-comparison.py` compares against (now pinned by full SHA), which the shallow checkout lacks.
- Logo: a weathered-steel plate with a C cut through it on a layered rust shield (`docs/assets/logo/`), with PNG sizes, a favicon and a 1280×640 GitHub social preview; shown at the top of the README.
- Phase 4, `corten-std`: `refine` (`Bounded`, `bounded!` proved at check time, runtime-checked `new`/`checked_add`/`copy_into`), `label` (`Labeled` over four levels; only `Public` reaches a sink; `declassify` needs a `DeclassifyCap` and writes a log record), `sync` (`lock_order!`, `OrderedMutex`; locks against the order do not compile). The manifest gains `declassify NAME`. 11 rejection fixtures with exact messages, 7 of 7 mutations caught. `docs/gates/phase-4.md`.
- Phase 3b trial (question 10): `crates/corten-lints` builds `corten-driver`, rustc on a pinned nightly with seven lints (must-use on every return, labelled parameters on exported functions, public interior-mutable statics, `unsafe` from non-std macros, direct `from_template` calls, blocking calls in async, Rc/Arc cycles of types with a destructor). `cargo corten check` and `build` run them in a second pass and require the driver (owner decision 10, with the must-use rule narrowed to functions in the checked crate). `scripts/build-driver.sh`. Corpus: 167 of 174 detected, 0 of 174 falsely rejected; CWE-493, 500, 607, 1091 and 1322 verified (141 of 175). `docs/gates/phase-3b.md`.

- Phase 3, `corten-runtime`: a supervision tree (`one_for_one`, `Permanent`/`Transient`/`Temporary`, a restart-intensity limit, cooperative shutdown) that contains a panic without `catch_unwind`.
- Phase 3, `corten-sandbox`: a Landlock launcher (ABI v4 required, exit 3 otherwise) with `--ro`/`--rw`/`--exec`/`--system`/`--allow-net`, and a layer 5 mode that turns a signed capability manifest into the rules. Owner decision 11: the `landlock` crate, with Unicode-3.0 allowed in `deny.toml`.
- Phase 3, `corten-broker`: a process broker (deadline, input and output quotas, cleared environment, no descriptors), a Wasm broker on `wasmi` 2.0.0 (owner decision 12; no imports, fuel, memory and output limits) and size-checked IPC frames.
- `cargo corten build` (Linux): profile and dependency policy, then `cargo vendor`, then an offline `cargo build --release` inside `corten-sandbox`; `--sbom` (CycloneDX 1.5) and `--provenance` (unsigned in-toto v1 / SLSA v1, with a dependency-free SHA-256). `scripts/hermetic-smoke.sh` tests it end to end and runs in CI.
- Layer 3 dependency policy in `cargo corten check` and `build`: reachable dependencies whose `unsafe` macros or proc macros the local code uses are refused, as is a ban list (backtracking regex engines, `libxml`); fail closed on scan limits; operator allowlist `--allow-dep` / `CORTEN_ALLOW_DEPS`. Closes the Phase 1 dependency-macro bypass except for allowlisted packages.
- Layer 4: `action.yml`, a composite GitHub Action running `cargo corten check` or `build`; a CI self-test builds a fresh crate with it.
- `cargo corten check` runs inside `corten-sandbox` on Linux, like `build` (owner decision); off Linux it warns. Local path dependencies outside the workspace are granted read-only.
- `corten-sandbox` refuses to start while a descriptor above 2 lacks close-on-exec (owner decision), after CI showed the runner's leaked descriptors reaching the sandboxed child. `scripts/close-leaked-fds.sh` closes them; CI and the action use it.
- Corpus: five Phase 3 cases and the `//@ fake-dep:` directive; CWE-403 verified (136 of 175). `docs/gates/phase-3.md`, with the defects found during the phase.
- Spec open questions 11 and 12 decided, and question 10 set to a Phase 3b trial.
- Phase 2, `corten-std`: `PathSeg`/`RelPath` per docs/pathseg.md; `DirCap` on `openat2` (Linux; refused elsewhere) with exclusive 0600 temp files; typed sinks with compile-time templates and no raw constructors (`sql!`, `html!`, `process!`, `log_record!`, `text!`, `ldap_filter!`, `ldap_dn!`, `xpath!`, `xquery!`, `HeaderValue`, `SetCookie`, `CsvCell`) and driver traits that accept only them; `Secret`; the Ed25519-signed capability manifest.
- Corpus: 76 Phase 2 cases (path, process and sink rows), 0 false rejections; 50 rows newly verified (135 of 175 in all). Ledger column `review`: 26 encoder-backed rows wait for an independent review.
- Corpus runner: per-worker target directories; `//@ edition:`; review-aware `--mark-verified`.
- `docs/gates/phase-2.md`: three defects found and fixed during the phase (`<{}>` in `html!`, check-time evaluation of template assertions, `openat2` mode), and the known `from_template` check-versus-build gap.
- Phase 1 profile in `cargo corten check`: clippy-driver wraps every local crate; forbidden lints `unsafe_code`, `unused_must_use`, `disallowed_methods`/`disallowed_types` (ambient `std` authority, `catch_unwind`, destructor-skipping APIs), `arithmetic_side_effects`, `as_conversions`, `let_underscore_must_use`, `mem_forget`; `overflow-checks=on`; a checker-owned `clippy.toml` in a private directory.
- Overrides found by measurement: forced `[env]` `CLIPPY_CONF_DIR` and `RUSTC_BOOTSTRAP` pinned with `cargo --config`; a repository `clippy.toml` ignored; local path dependencies outside the workspace linted. Each has a test with a live control.
- `corten-corpus` and `corpus/`: 93 cases; 85 E rows verified with 0 false rejections; `docs/gates/phase-1.md` with the bypass hunt (two bypasses found: `thread::join` as a catch-all, and `unsafe` from a dependency's macro, recorded on the 43 rows it affects).
- `corten-ledger`: CSV writer and `set_status`, round-tripping the ledger byte for byte.
- Spec open question 10: custom lints need a nightly-based lint driver.
- Phase 0: the nine open decisions settled (panel position kept on all nine) and kill thresholds set (false rejection 5%; bypass of more than half of a phase's E claims). The 14 doubly disputed ids decided in the ledger; 11 drafted E ids moved to C with reasons. The ledger now holds E 175 / C 721 / O 26 / N 22.
- Ledger columns `bucket`, `bucket_reason`, `phase`, `proof_kind`; every E row has a mechanism, TCB assumption, prelude-only flag and planned proof test.
- `corten-ledger`: `check` (the Phase 0 gate, plus a guard against formula-leading cells) and `totals`. Runs in CI.
- `docs/pathseg.md` (normative `PathSeg` grammar and `DirCap` monitor, adding `RESOLVE_NO_XDEV`) and `docs/tcb.md` (TCB, fail-closed rule, implementation-defined behaviour).
- `main` ruleset: pull request with the four CI checks required, no bypass, no force-push or deletion, linear history. `.github/CODEOWNERS`. Signed commits not yet required.
- Cargo workspace (edition 2024, Rust 1.99.1 pinned in `rust-toolchain.toml`) with workspace lints, `clippy.toml`, `deny.toml` and a nextest profile.
- `cargo-corten`: `cargo corten check` builds a crate with `-F unsafe_code`, supplied through `CARGO_ENCODED_RUSTFLAGS`, and overrides `rustc-wrapper`, `rustc-workspace-wrapper`, `[build] rustc` and every `rustflags` source the checked repository could use to weaken it. Each override has a test with a control showing the bypass works against plain cargo. No dependencies.
- `corten-std`: placeholder crate for the closed prelude.
- CI: fmt, clippy, rustdoc, nextest, doctests, cargo-deny and a gitleaks history scan; actions pinned by SHA.
- Pre-commit: `cargo fmt` on commit; clippy, `cargo test` and `cargo audit` on push (generated by `init-gates.sh`).
- Spec section 10: the measured wrapper bypass and the overrides it requires.

### Changed

- `corten-std` public functions take labelled arguments where two parameters shared a type: `manifest::verify` and `Capabilities::load` (`Signature`, `PublicKey`), `ProcessInvocation::new` (`Options`, `Operands`), `SetCookie::new` (`CookieName`, `CookieValue`). `Capabilities::load` checks its map inserts.
- Rust applicability in the ledger now comes from the per-CWE review instead of MITRE's language tags: 136 rows changed. The tag-based count of 853 CWEs applying to Rust counted 68 hardware and process weaknesses and 11 constructs Rust lacks, and missed 17 that safe Rust can write.
