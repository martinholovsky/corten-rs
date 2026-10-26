# cargo-corten

`cargo corten check` builds a crate under the Corten profile, with flags the checker supplies itself (spec section 10, layer 2). Today the profile is one rule: `-F unsafe_code`. The Clippy lint set from the spec's Phase 1 comes next.

```console
$ cargo install --path crates/cargo-corten --locked
$ cargo corten check                         # in the crate to check
$ cargo corten check --manifest-path path/to/Cargo.toml
```

It runs `cargo check --workspace --all-targets`. Exit status: 0 the build passed, 1 it failed (a profile rule or an ordinary compile error; they are not told apart yet), 2 usage or environment error.

## What it overrides

A repository can carry cargo configuration that changes what rustc receives. Cargo reads `.cargo/config.toml` from the **current directory** and every ancestor, then `$CARGO_HOME`; not from the `--manifest-path` directory. The checker sets the child's environment so none of it can weaken the profile:

| Source | How it could weaken the profile | What the checker does | Test |
| --- | --- | --- | --- |
| `RUSTFLAGS`, `[build] rustflags`, `[target.*] rustflags` | Add `-A unsafe_code` | Sets `CARGO_ENCODED_RUSTFLAGS`, which replaces all of them; removes `RUSTFLAGS` and `CARGO_BUILD_RUSTFLAGS` | `operator_rustflags_cannot_lower_the_profile`, `config_rustflags_cannot_lower_the_profile` |
| `[build] rustc-wrapper` | A wrapper drops `-F unsafe_code` before calling rustc | Sets `RUSTC_WRAPPER` to the empty string | `config_rustc_wrapper_is_not_run` |
| `[build] rustc-workspace-wrapper` | Same, for workspace members only | Sets `RUSTC_WORKSPACE_WRAPPER` to the empty string | `config_rustc_workspace_wrapper_is_not_run` |
| `[build] rustc` | A replacement rustc ignores the flags | Sets `RUSTC` to the operator's `RUSTC`, or the `rustc` beside the running `cargo` | `config_rustc_replacement_is_not_run` |

`[target.*] rustflags` is covered by cargo's documented precedence (`CARGO_ENCODED_RUSTFLAGS` first, the sources mutually exclusive) and has no test of its own yet.

Each hostile-configuration test first shows the configuration bypasses plain `cargo check` with the same flags (the control), then that the checker rejects the unsafe program and still accepts the matched safe one. Removing the overrides makes all three wrapper tests fail (mutation-checked 2026-10-26).

Measured on cargo 1.99.1, 2026-10-26: with `[build] rustc-wrapper` pointing at a script that drops `-F`, `CARGO_ENCODED_RUSTFLAGS="-F unsafe_code" cargo check` built an unsafe block; adding `RUSTC_WRAPPER=` made it fail with E0453.

A side effect: an operator's own wrapper, such as `sccache`, is not used under the checker.

## What it does not cover yet

These are known gaps, not claims. Each needs a test before it can be called handled.

- **The toolchain is chosen by the checked repository.** Run as `cargo corten`, the rustup proxy has already picked the toolchain from the repository's `rust-toolchain.toml`, and rustup documents a `path` key there that names a custom toolchain. Neither the key nor its effect on the checker has been tested here.
- **Build scripts and proc macros of the checked crate run** during the check, with the operator's privileges. Check untrusted code only inside a sandbox; layer 4 (the CI gate) is where that belongs.
- **`unsafe` produced by a macro from another crate** may not trigger the `unsafe_code` lint. Unverified; it belongs in the bypass hunt.
- **Registry and git dependencies** are compiled by cargo with `--cap-lints allow` (cargo's documented behaviour for non-local packages; not measured here), so the profile does not reach them. That is layer 3 (spec section 10).
