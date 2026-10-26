# Phase 1 gate: profile on stock Rust

Date: 2026-10-26. Toolchain: Rust 1.99.1 (rustc, cargo, clippy-driver). Gate, from spec section 9: "for each E id this phase claims, a program exhibiting the weakness fails to build, and a matched benign program builds. Report both rates."

**Result: not fully passed.** 85 of the 91 E ids Phase 1 claims are verified. 6 wait for mechanisms Phase 1 could not build on stable Clippy (open question 10, spec section 8), plus one bypass the hunt found. Kill criteria are not triggered, but a bypass reaches 41 of the 91 claims, close to the "more than half" threshold. Details below.

## 1. What Phase 1 built

`cargo corten check` builds every crate (workspace members and local path dependencies) through `clippy-driver`. It supplies its own flags and Clippy configuration:

- `-C overflow-checks=on`;
- forbidden rustc lints: `unsafe_code`, `unused_must_use`;
- forbidden Clippy lints: `disallowed_methods` and `disallowed_types` (ambient filesystem, environment, process, network, clock, `catch_unwind`, destructor-skipping APIs), `arithmetic_side_effects`, `as_conversions`, `let_underscore_must_use`, `mem_forget`.

It also overrides each configuration source the checked repository could use to weaken this; every override has a test with a live control (crates/cargo-corten/README.md).

## 2. Corpus result

`cargo run -p corten-corpus -- --checker target/debug/cargo-corten` over every E row that has a case. Generated output: [`corpus-report.md`](corpus-report.md).

| Measure | Phase 1 (91 cases) | All cases (93; adds 2 Phase 4 rows) |
| --- | ---: | ---: |
| Detection: every bad program rejected for the expected reason | 85 of 91 | 85 of 93 |
| False rejection: matched good program failed to build | **0 of 91** | 0 of 93 |
| Controls failed: plain cargo did not build a `checker` case's bad program | 0 | 0 |
| Broken cases | 0 | 0 |
| Verified rests only on syntax Rust does not have (weakest evidence) | 11 | 11 |

How a case counts:

- `checker` kind: plain cargo builds every `bad*.rs` (so the profile, not the language, is what rejects it); `cargo corten check` rejects each one with the text in its `//@ expect:` line; it accepts `good.rs`.
- `language` kind: plain cargo rejects `bad.rs` with the expected text (for example E0381 for an uninitialised variable); the checker accepts `good.rs`.
- A row is verified only when **every** variant of the weakness in its directory is rejected.

The 11 "construct absent" cases (CWE-395, 397, 460, 484, 491, 584, 621, 624, 627, 914, 1055) are programs written in another language's syntax: Rust has no `try`/`catch`, `switch`, `class` or `$variable`. They meet the letter of the E rule, but they show only that the construct does not exist, which was already known.

## 3. Not verified, and why

| CWE | What the checker accepts | Needs |
| --- | --- | --- |
| 252 | Ignoring a `bool` status (`bad-bool.rs`) | Must-use on every non-unit return value: a custom lint |
| 493, 500 | A `pub static` with interior mutability (`AtomicU32`) | A lint against interior-mutable public statics: custom |
| 607 | A `pub static Mutex<Vec<_>>` | Same lint |
| 683 | Two same-typed arguments in the wrong order | Labelled same-typed parameters: custom lint |
| 396 | `thread::spawn(..).join()` used as a catch-all (bypass hunt) | Banning `JoinHandle::join` or restricting panics to supervised components (Phase 3); banning join outright would reject ordinary code |
| 1091 (Phase 4) | An `Rc` cycle that never drops | The no-cycles-of-linear-resources rule |
| 1322 (Phase 4) | `std::thread::sleep` inside `async fn` | The `blocking` effect |

The custom lints need rustc internals (dylint or a rustc driver), which means a pinned nightly toolchain inside the checker. That is recorded as open question 10 in spec section 8, not decided here.

## 4. Bypass hunt

Each attempt was measured on Rust 1.99.1. Tests that pin a result are named.

| Attempt | Result | Pinned by |
| --- | --- | --- |
| In-source `#![allow(unsafe_code)]` or `#[expect]` | Rejected (E0453) | `rejects_unsafe_that_allows_itself` |
| `.cargo/config.toml` `rustflags`, `rustc-wrapper`, `rustc-workspace-wrapper`, `[build] rustc` | Overridden | `config_*` tests |
| Repository `clippy.toml` / `.clippy.toml` emptying the ban list | Ignored: `CLIPPY_CONF_DIR` points at the checker's file | `repository_clippy_toml_cannot_empty_the_ban_list` |
| `[env] CLIPPY_CONF_DIR = { force = true }` in the repository's config | Was a bypass; now pinned with `--config` | `forced_env_clippy_conf_dir_cannot_replace_the_ban_list` |
| `[env] RUSTC_BOOTSTRAP = "1"`, enabling nightly features such as `allow_internal_unsafe` on stable | Was a bypass; now pinned to `-1` | `forced_env_rustc_bootstrap_cannot_unlock_nightly_features` |
| A banned call moved into a local path dependency outside the workspace | Was a bypass (Clippy ran on workspace members only); clippy-driver now wraps every crate | `local_path_dependency_outside_the_workspace_is_linted` (mutation-checked) |
| A banned function used by pointer or renamed import | Rejected | measured by hand |
| `#[no_mangle]` replacing `free()` in an edition-2021 crate | Rejected ("usage of the unsafe `no_mangle` attribute") | `corpus/CWE-762/bad-no-mangle.rs` |
| `thread::spawn(..).join()` as a catch-all handler | **Bypass** (CWE-396) | `corpus/CWE-396/bad-thread.rs` |
| **`unsafe` inside a macro exported by a registry dependency** | **Bypass.** rustc does not report `unsafe_code` in expansions of external macros, so a dependency can inject an unsafe block into the checked crate | `known_bypass_unsafe_from_a_dependency_macro` |
| Arithmetic Clippy can evaluate as a constant (`let a: u8 = 200; a + 100`) | Not linted by `arithmetic_side_effects`; overflow is still a runtime panic (`overflow-checks=on`) and overflow is C in the ledger | measured by hand |
| rustc soundness hole #25860 (implied bounds), in the forms tried | Rejected by rustc 1.99.1 ("lifetime may not live long enough"). This does not show the hole is closed; other forms were not tried | measured by hand |

**The dependency-macro bypass** reaches every verified claim whose proof rests on `-F unsafe_code`: 41 of the 91 Phase 1 claims. Those rows' `tcb_assumption` now says the claim holds only while no dependency exports a macro that expands to `unsafe`. Closing it is layer 3 work (Phase 3): the dependency policy must refuse dependencies whose macros or procedural macros can emit `unsafe`. Until then, the claims hold for crates with no such dependency.

## 5. Kill criteria (thresholds set by the owner, spec section 11)

- **False rejection limit 5%:** 0 of 91 (0%). Not triggered.
- **Bypass of more than half of the phase's E claims:** the dependency-macro bypass reaches 41 of 91 (45%); with CWE-396, 42 of 91 (46%). Not triggered, but close, and the 41 are conditional on dependencies rather than evaded outright. The owner may read this differently.

## 6. Limits of this evidence

- The corpus has one to three variants per id, written by the same author as the checker. The spec's bypass hunt calls for an adversarial red team (for example the cross-vendor panel method); this hunt was not that.
- Cases are small, dependency-free programs. False rejection on real code is not measured here; that needs a benign corpus of real crates.
- The ban list is a denylist over `std` (`crates/cargo-corten/src/profile.rs`); the closed prelude is the deny-by-default answer.
