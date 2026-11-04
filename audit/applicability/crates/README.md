# Weaknesses safe Rust can write through a crate

The applicability audit first asked whether safe Rust can write a weakness with `std` alone. A crate with a safe API widens that: for the rows below, a common crate offers the operation `std` does not, and every probe here compiles under `#![forbid(unsafe_code)]`. Each review row (`../rows-*.csv`) cites its probe and cites no program, because `scripts/applicability-check.sh` checks programs against stock rustc, which cannot pull in a crate.

Measured 2026-11-04 on macOS (owner decision of the same day: crate-dependent verdicts are recorded as reasoning that cites the crate, its version and this measurement). These probes are **not built by CI**; re-run them by hand when a version changes:

```
cargo run --release --manifest-path audit/applicability/crates/Cargo.toml --bin <probe>
```

| CWE | Probe | Crate | Observed |
| --- | --- | --- | --- |
| 560 | `cwe560_umask` | rustix 1.1.6, `process::umask` | the umask set to 0644 (was 022) |
| 403 | `cwe403_fd_leak` | rustix 1.1.6, `io::fcntl_setfd` | a child shell read the parent's descriptor 3 |
| 403 | `cwe403_nix` | nix 0.31.3, `fcntl::fcntl(F_SETFD)` | the same |
| 910 | `cwe910_reuse` | nix 0.31.3, `unistd::close` on a `File`'s number | the next open reused 3, and the stale `File` for `/etc/hosts` read `/etc/shells` (release build) |
| 1341 | `cwe1341_double_close` | nix 0.31.3, `unistd::close` twice | `Ok`, then `EBADF` (a debug build aborts on std's I/O-safety check when the `File` drops) |
| 134 | `cwe134_strfmt` | strfmt 0.2.6, `strfmt` | a format string from the command line printed a value the program never meant to show; no memory is corrupted |

Under Corten these crates are refused unless the operator admits them (`crates/cargo-corten/README.md`, dependency policy), and `docs/dep-policy.example` bans each API above for an operator who does. Each corpus case carries a `bad-<crate>.rs` variant for the refusal.

Checked and still needing `unsafe` (2026-11-04): `ctor` 1.0.13 requires `#[ctor(unsafe)]`, which `forbid(unsafe_code)` refuses (E0453), so CWE-1063 holds; `signal-hook` 0.4.6's `low_level::register` is an `unsafe fn` (E0133) and its safe `flag::register` only sets an atomic flag, so CWE-364, 432, 479, 828 and 831 hold; nix 0.31.3 has no `getlogin`, so CWE-558 holds.
