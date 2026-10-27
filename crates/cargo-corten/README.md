# cargo-corten

`cargo corten check` builds a crate under the Corten profile, with flags and a Clippy configuration the checker supplies itself (spec section 10, layer 2). The profile is in [`src/profile.rs`](src/profile.rs):

- `-C overflow-checks=on`;
- forbidden rustc lints: `unsafe_code`, `unused_must_use`;
- forbidden Clippy lints: `disallowed_methods`, `disallowed_types`, `arithmetic_side_effects`, `as_conversions`, `let_underscore_must_use`, `mem_forget`;
- a Clippy configuration banning ambient filesystem, environment, process, network and clock APIs, `catch_unwind`, and the APIs that skip a destructor. This is a denylist over `std`, so it can miss an API; the closed prelude (`corten-std`) is the deny-by-default answer.

"Forbidden" means `-F`: an in-source `allow` or `expect` cannot lower it (E0453). The Clippy toolchain component is required.

```console
$ cargo install --path crates/cargo-corten --locked
$ cargo corten check                         # in the crate to check
$ cargo corten check --manifest-path path/to/Cargo.toml
```

It runs `cargo check --workspace --all-targets` with `clippy-driver` wrapping every crate. Clippy disables itself for registry and git dependencies (built with `--cap-lints allow`), so only the workspace and local path dependencies are linted. The checker writes its `clippy.toml` into a fresh private directory (`create_dir`, mode 0700) and removes it afterwards. Exit status: 0 the build passed, 1 it failed (a profile rule or an ordinary compile error; they are not told apart yet), 2 usage or environment error.

## What it overrides

A repository can carry cargo configuration that changes what rustc receives. Cargo reads `.cargo/config.toml` from the **current directory** and every ancestor, then `$CARGO_HOME`; not from the `--manifest-path` directory. The checker sets the child's environment so none of it can weaken the profile:

| Source | How it could weaken the profile | What the checker does | Test |
| --- | --- | --- | --- |
| `RUSTFLAGS`, `[build] rustflags`, `[target.*] rustflags` | Add `-A unsafe_code` | Sets `CARGO_ENCODED_RUSTFLAGS`, which replaces all of them; removes `RUSTFLAGS` and `CARGO_BUILD_RUSTFLAGS` | `operator_rustflags_cannot_lower_the_profile`, `config_rustflags_cannot_lower_the_profile` |
| `[build] rustc-wrapper` | A wrapper drops `-F unsafe_code` before calling rustc | Sets `RUSTC_WRAPPER` to the toolchain's `clippy-driver` | `config_rustc_wrapper_is_not_run` |
| `[build] rustc-workspace-wrapper` | Same, for workspace members only | Sets `RUSTC_WORKSPACE_WRAPPER` to the empty string | `config_rustc_workspace_wrapper_is_not_run` |
| `clippy.toml` or `.clippy.toml` in the repository | An empty ban list | Sets `CLIPPY_CONF_DIR` to the checker's own directory | `repository_clippy_toml_cannot_empty_the_ban_list` |
| `[env] CLIPPY_CONF_DIR = { value = "...", force = true }` | Points Clippy at the repository's own (empty) ban list; cargo sets `[env]` for every compiler it runs, overriding the checker's variable | Pins it with `--config env.CLIPPY_CONF_DIR.value=... --config env.CLIPPY_CONF_DIR.force=true`, which outranks configuration files | `forced_env_clippy_conf_dir_cannot_replace_the_ban_list` |
| `[env] RUSTC_BOOTSTRAP = { value = "1", force = true }` | Enables nightly features on stable, such as `allow_internal_unsafe` | Pins `RUSTC_BOOTSTRAP=-1` the same way | `forced_env_rustc_bootstrap_cannot_unlock_nightly_features` |
| A banned call in a local path dependency outside the workspace | Clippy ran on workspace members only | `clippy-driver` wraps every crate | `local_path_dependency_outside_the_workspace_is_linted` |
| `[build] rustc` | A replacement rustc ignores the flags | Sets `RUSTC` to the operator's `RUSTC`, or the `rustc` beside the running `cargo` | `config_rustc_replacement_is_not_run` |

`[target.*] rustflags` is covered by cargo's documented precedence (`CARGO_ENCODED_RUSTFLAGS` first, the sources mutually exclusive) and has no test of its own yet.

Each hostile-configuration test first shows the configuration bypasses plain `cargo check` with the same flags (the control), then that the checker rejects the bad program and still accepts the matched safe one. Removing the wrapper overrides makes all three wrapper tests fail, and restricting `clippy-driver` to workspace members makes the path-dependency test fail (both mutation-checked 2026-10-26).

Measured on cargo 1.99.1, 2026-10-26: `--config 'env.CLIPPY_CONF_DIR={value=...,force=true}'` (an inline table) did not override the repository's forced entry; the dotted keys `env.CLIPPY_CONF_DIR.value` and `env.CLIPPY_CONF_DIR.force` did.

Measured on cargo 1.99.1, 2026-10-26: with `[build] rustc-wrapper` pointing at a script that drops `-F`, `CARGO_ENCODED_RUSTFLAGS="-F unsafe_code" cargo check` built an unsafe block; adding `RUSTC_WRAPPER=` made it fail with E0453.

A side effect: an operator's own wrapper, such as `sccache`, is not used under the checker.

## What it does not cover yet

These are known gaps, not claims. Each needs a test before it can be called handled.

- **The toolchain is chosen by the checked repository.** Run as `cargo corten`, the rustup proxy has already picked the toolchain from the repository's `rust-toolchain.toml`, and rustup documents a `path` key there that names a custom toolchain. Neither the key nor its effect on the checker has been tested here.
- **Build scripts and proc macros of the checked crate run** during the check, with the operator's privileges. A build script could, for example, rewrite the checker's `clippy.toml` before Clippy reads it. Check untrusted code only inside a sandbox; layer 4 (the CI gate) is where that belongs.
- **Build scripts of workspace crates are linted too** (measured: `std::env::var` in a `build.rs` is rejected), so a build script that reads its environment or files does not pass. Corten's spec does not allow unrestricted build scripts; whether to exempt them is open.
- **`unsafe` produced by a macro from a registry or git dependency is not reported.** Measured: rustc does not report `unsafe_code` inside expansions of external macros, so a dependency's `macro_rules!` can put an unsafe block into the checked crate and the check passes. Pinned by `known_bypass_unsafe_from_a_dependency_macro`; layer 3 must close it (docs/gates/phase-1.md).
- **A repository's `[env]` table can still set other variables for the compiler**, for example `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES`, which run code inside rustc. Only `CLIPPY_CONF_DIR` and `RUSTC_BOOTSTRAP` are pinned. Like build scripts, this is code execution by the checked repository, which only a sandbox contains.
- **Registry and git dependencies** are compiled by cargo with `--cap-lints allow` (cargo's documented behaviour for non-local packages; not measured here), so the profile does not reach them. That is layer 3 (spec section 10).
