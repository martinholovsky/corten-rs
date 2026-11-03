# Phase 6: mitigating the CWEs that remain under Rust and Corten

Status: **in progress** (started 2026-11-01). The plan is [`../residual-mitigation.md`](../residual-mitigation.md); the per-CWE map is [`../residual-cwes.md`](../residual-cwes.md). Owner decisions on 2026-11-01: spec section 8, questions 13 to 15, the recommendation on all three. Nothing below is a result until its row says so.

Each item ships the way earlier phases did:
- a corpus case per CWE it claims, with every known way of writing the weakness as a `bad-*.rs`;
- detection and false-rejection rates with their totals (AGENTS.md rule 2);
- mutation checks for each new control;
- the Linux checks in the container (AGENTS.md).

A strategy that only strengthens C moves no bucket.

## Batches

| Batch | Strategies (proposal numbers) | Status | Blocked on |
| --- | --- | --- | --- |
| 1 | Decision 3: the ledger's `strategy` column, checked by `corten-ledger check` | **done** (2026-11-01, below) | |
| 2 | 15 lints; 9 labels on errors, logs and debug output | lints **done** (2026-11-01, below); labels not started | |
| 3 | 4 budgets and timeouts; 3 safe deserialization and `ConfigCap`; 8 DirCap extensions | not started | |
| 4 | 2 authorization and authentication proof types: prototype, adopt only at 0 false rejections (question 14) | not started | |
| 5 | 10 cryptography and randomness; 7 TLS and network capabilities (question 13) | strategy 10 **done** (2026-11-01, below): `corten_std::crypto`, `corten_std::random`, weak-primitive bans; strategy 7 **built** (2026-11-02, below): `NetCap` core, then resolution, DNS logging and the opt-in fallback ([`../netcap.md`](../netcap.md)) | |
| 6 | 6 web types; 11 credentials; 12 strict parsers; 13 contracts; 5 runtime; 14 supply chain | not started | |
| — | 1 the independent encoder review (25 rows) | blocked | The owner naming a reviewer (AGENTS.md rule 1: not the encoders' author; the AI pre-review is not the review of record) |
| — | 16 code-quality metrics; 17 assurance tooling; 18 out of scope | reported, not gated | Spec section 7 |

## Batch 1 result (2026-11-01)

- **Ledger.** `ledger/cwe-ledger.csv` gains a `strategy` column. 641 rows carry one of the 18 strategies in `audit/residual/strategies.csv`; the other 303 are empty. Apart from the new column, the ledger is byte-identical (checked by removing the column again).
- **Gate.** `corten-ledger check` now also requires a known strategy on every CWE safe Rust can still write under Corten, and refuses one on a CWE safe Rust cannot write. A verified E row may keep its strategy, so `--mark-verified` never leaves the gate failing.
- **Gate refusals, each watched on a copy of the real ledger:**
  - blanking the 16 `authz-types` rows: 16 problems, exit 1;
  - a strategy on CWE-787, which safe Rust cannot write: exit 1;
  - renaming `budgets` to an unknown value: 24 problems, exit 1;
  - removing `strategies.csv`: exit 2.
- **Unit tests.** They cover each rule and the missing-column error.
- **Single source.** The first assignment file (`audit/residual/assignment.csv`) was folded into the ledger and removed. `scripts/residual-map.py` now reads the ledger, and its output is unchanged apart from its header.

## Batch 2, lints result (2026-11-01)

15 lints added to the checker's forbidden lists (`crates/cargo-corten/src/profile.rs`). They are aids: they move no bucket and claim no elimination.

| Lint | CWE |
| --- | --- |
| rustc `dead_code` | 561 |
| rustc `deprecated` | 477 |
| `clippy::precedence` | 783 |
| `clippy::float_cmp`, `float_cmp_const` | 1077 |
| `clippy::dbg_macro`, `todo`, `unimplemented` | 489 |
| `clippy::eq_op`, `absurd_extreme_comparisons`, `impossible_comparisons`, `redundant_comparisons`, `overly_complex_bool_expr`, `nonminimal_bool` | 570, 571 |
| `clippy::short_circuit_statement` | 768 |

Each lint was checked three ways:

1. **The name is known to Clippy 0.1.99.** A probe forbade every candidate plus a made-up name; only the made-up one was reported unknown. An unknown lint is only a warning, so a misspelled lint would be an inert control.
2. **It fires.** One program with an instance of each weakness gave 16 errors, one per candidate, `unused_assignments` included.
3. **It rejects no good program.** Linux, corpus run: with all 16 candidates, 169 of 169 detected and **1 of 169** falsely rejected. `unused_assignments` (CWE-563) rejected `corpus/CWE-482/good.rs`, a benign dead store, so it was dropped rather than the good program changed. With the 15 kept: **169 of 169 detected, 0 of 169 falsely rejected**. Also on Linux: `cargo-corten` tests 57 of 57, Clippy clean, hermetic smoke test 3 of 3.

Not covered by this batch: CWE-563 (its lint was dropped, above), and the other CWEs in the `lints` group for which no candidate was tried. They keep their strategy until a lint or a prelude change covers them.

## Batch 5, step 1: licences and supply chain (measured 2026-11-01)

Question 13 asks for this review before the owner approves any crate. Nothing is added to the workspace by it.

**Method.**
- Releases and licences come from the crates.io API on 2026-11-01.
- Each candidate set is a scratch crate (edition 2024, Rust 1.99.1) checked with the repository's own `deny.toml`: `cargo deny check advisories bans licenses sources`, cargo-deny 0.20.2, advisory database at commit `2295466` (2026-10-30).
- "Packages" counts `[[package]]` entries in the set's `Cargo.lock`: every target platform, and the scratch crate itself.
- Native code is counted in the downloaded sources.
- Building the sets runs their build scripts, so it was measured afterwards in the container (Build measurements, below).

### Releases and licences

| Crate | Latest | Released | Licence |
| --- | --- | --- | --- |
| `chacha20poly1305` | 0.11.0 | 2026-06-28 | Apache-2.0 OR MIT |
| `aes-gcm-siv` | 0.12.1 | 2026-08-21 | MIT OR Apache-2.0 |
| `argon2` | 0.6.0 | 2026-08-27 | MIT OR Apache-2.0 |
| `getrandom` | 0.4.3 | 2026-06-17 | MIT OR Apache-2.0 |
| `ed25519-compact` (in the TCB already) | 2.6.0 | 2026-09-25 | MIT |
| `ring` | 0.17.14 | **2025-03-11** | Apache-2.0 AND ISC |
| `aws-lc-rs` | 1.19.0 | 2026-10-28 | ISC AND (Apache-2.0 OR ISC) |
| `aws-lc-sys` | 0.47.0 | 2026-10-28 | seven terms, all permissive (ISC, Apache-2.0, MIT, BSD-3-Clause, MIT-0) |
| `rustls` | 0.23.46 | 2026-10-14 | Apache-2.0 OR ISC OR MIT |
| `rustls-webpki` | 0.103.16 | 2026-10-20 | ISC |
| `rustls-native-certs` | 0.8.5 | 2026-10-13 | Apache-2.0 OR ISC OR MIT |
| `rustls-platform-verifier` | 0.7.1 | 2026-09-24 | MIT OR Apache-2.0 |
| `webpki-roots` | 1.0.11 | 2026-10-23 | **CDLA-Permissive-2.0** |

### Candidate sets against `deny.toml`

| Set | Packages | `cargo deny` | Native code |
| --- | ---: | --- | --- |
| RustCrypto: `chacha20poly1305`, `aes-gcm-siv`, `argon2`, `getrandom`, `ed25519-compact` | 32 | passes | none |
| `ring` | 20 | passes | `cc`; 145 C, assembly and Perl files; 57 prebuilt object files (Windows) |
| `aws-lc-rs` | 17 | passes | `cc` and `cmake`; 1,493 C, assembly and Perl files; 97 prebuilt object files (Windows) |
| `rustls` on `ring` + `rustls-native-certs` | 36 | passes | as `ring` |
| `rustls` on `aws-lc-rs` + `rustls-native-certs` | 45 | passes | as `aws-lc-rs` |
| `rustls` on `ring` + `rustls-platform-verifier` | 61 | **refused**: `webpki-root-certs` is CDLA-Permissive-2.0 | as `ring` |
| `rustls` (default, `aws-lc-rs`) + `webpki-roots` | 37 | **refused**: `webpki-roots` is CDLA-Permissive-2.0 | as `aws-lc-rs` |
| RustCrypto set (no `aes-gcm-siv`) + `rustls` on `ring` + `rustls-native-certs` | 60 | **refused**: `ring` needs `getrandom` 0.2, the prelude 0.4 (`multiple-versions = "deny"`) | as `ring` |
| RustCrypto set (no `aes-gcm-siv`) + `rustls` on `aws-lc-rs` + `rustls-native-certs` | 67 | passes | as `aws-lc-rs` |

The refusals show the gate can fail; every passing set passed all four checks.

### Findings

- **Every bundled root store is CDLA-Permissive-2.0**, so a TLS client with built-in roots needs that licence allowed. The operating system's store (`rustls-native-certs`) passes today; it needs a CA bundle on the host, which a minimal container may lack.
- **`ring`:** no release since 0.17.14 (2025-03-11). Commits continue (the latest on 2026-07-22). The "unmaintained" advisory RUSTSEC-2025-0007 was withdrawn two days after it was filed. `ring` offers PBKDF2 and no memory-hard password hash (no `argon2` or `scrypt` in its source), so password hashing needs another crate either way. Its `getrandom` 0.2 cannot sit beside the prelude's `getrandom` 0.4 under the current policy.
- **`aws-lc-rs`:** released often, and the default provider of `rustls`. It is the largest native code base here and needs `cmake` at build time. It has five advisories in 2026 (RUSTSEC-2026-0044 to 0048, against `aws-lc-sys`), all fixed in 0.39.0 and later. Its README describes a FIPS build (26 mentions); Corten needs FIPS only if a deployer asks for it.
- **`rustls`:** five advisories in 2026 and `rustls-webpki` five, all fixed in the versions above. Four `rustls` advisories and the fixed release landed the same day (2026-10-14). CI's weekly `cargo deny` run is what would catch the next one.
- **RustCrypto:** pure Rust, no build scripts that compile C. According to its README, `chacha20poly1305` has had one NCC Group audit with no significant findings. `aes-gcm-siv`'s README says the crate itself has never been audited. `argon2`'s README mentions no audit.

### Options for the owner (question 13)

1. **Prelude cryptography (strategy 10).**
   - (a) RustCrypto: `chacha20poly1305` used only as XChaCha20-Poly1305, so a random 192-bit nonce per message is safe and the library can manage nonces; `argon2` with a cost floor; `getrandom` for OS randomness; `ed25519-compact`, already in the TCB, for `Verified<T>`. No native code. `aes-gcm-siv` is not needed beside XChaCha20 and is unaudited, so it is left out.
   - (b) The TLS provider's own primitives for the AEAD, plus `argon2`. One cryptographic implementation fewer in the TCB, but the prelude's AEAD then rests on C and assembly.
2. **TLS provider (strategy 7).**
   - (a) `aws-lc-rs`. It passes beside the RustCrypto set, is released often and is `rustls`'s default. Costs: `cmake` and a C toolchain in the hermetic build, and the largest native code base.
   - (b) `ring`. It is smaller, but its `getrandom` 0.2 would need a `skip` in `deny.toml`, and it has not been released for 20 months.
3. **Root certificates.**
   - (a) The operating system's store only (`rustls-native-certs`). It passes today.
   - (b) Allow CDLA-Permissive-2.0 for `webpki-roots`, so built-in roots work where the host has none. This adds a licence to the policy, which is an owner decision.

**Recommendation:** 1(a), 2(a) and 3(a).
- 1(a) keeps the prelude's own cryptography in safe, native-free code.
- 2(a) is the only provider that passes beside it without a policy exception.
- 3(a) needs no licence change. 3(b) can be revisited when a deployment needs roots on a host without a CA bundle.

**Decision (owner, 2026-11-01):** 1(a), 2(a) and 3(a), the recommendation.

### Build measurements (Linux, 2026-11-01)

The chosen set (`chacha20poly1305`, `argon2`, `getrandom`, `ed25519-compact`, `rustls` on `aws-lc-rs`, `rustls-native-certs`; 67 packages) was built as an application crate.
- **Environment:** `docker.io/library/rust:1.99.1-slim-bookworm`, kernel 6.17.7, gcc 12.2.0, **no `cmake` installed**.
- **Checker:** built from this repository at `92b947c`, with `corten-driver` from `scripts/build-driver.sh`.

| Step | Result |
| --- | --- |
| Plain `cargo build --release` | passes. `aws-lc-sys` 0.47.0 reports `Building with: CC`: its `cc` builder, no `cmake` binary. The `cmake` crate is compiled but runs nothing |
| `cargo corten check`, policy admitting nothing (control) | refused, exit 1 |
| `cargo corten check`, policy admitting the six crates | **refused, exit 1**: 7 more packages need admission (`aead`, `crypto-common`, `hybrid-array`, `inout`, `rand_core`, `rustls-pki-types`, `typenum`) |
| `cargo corten check`, policy admitting those 13 | passes |
| `cargo corten build`, same 13 | passes inside `corten-sandbox`. The binary is built, and the provenance records `"sandboxed":true` |

**What this adds to the review.**
- **Admission is wider than the direct dependencies.** Layer 3 counts the packages an admitted crate re-exports as reachable (`crates/cargo-corten/src/deps.rs`), so an operator admitting these crates directly admits 13.
- **Wrap, never re-export.** When `corten-std` wraps them, its public API must not re-export their types, or every application using the prelude meets the same requirement.
- **No `cmake` binary.** `cmake` is not needed on Linux x86-64, so the sandbox's system-directory grant is enough.
- **The condition holds.** The decision's condition (a `cmake` build the sandbox refuses would reopen 2(a)) did not arise.

## Batch 5, strategy 10 result (2026-11-01)

`corten-std` gains two modules. No ledger row moves: the strategy strengthens C, and an E claim for prelude users needs corpus cases first (below).

- **`corten_std::random`.** Randomness comes only from the operating system's generator, through `getrandom`. There is no seedable generator, and a failure is an error, never a weaker source.
- **`corten_std::crypto`:**
  - `AeadKey`: XChaCha20-Poly1305. The library picks a random 192-bit nonce for every message, so the caller cannot choose or reuse one. A sealed message is a format-version byte, the nonce, the ciphertext and the tag. `open` returns one opaque error for every failure, and both directions are bounded at 16 MiB.
  - `password`: Argon2id at OWASP's recommended 19 MiB, 2 iterations, 1 lane, with a 16-byte salt (RFC 9106). `verify` refuses a stored hash below all five of OWASP's minimum configurations, and anything but Argon2id version 19. Values checked against the raw pages on 2026-11-01.
  - `verify_signed` returns `Verified<T>`, which only a successful Ed25519 check (or `map` on another `Verified`) can produce.
  - No dependency type appears in the public API, so an application using the prelude does not have to admit the crates (Build measurements, above).
- **Bans.** `docs/dep-policy.example` gains 24 ban lines:
  - MD5 (`md-5` and `md5`), SHA-1, DES and triple DES, RC4;
  - `SeedableRng::seed_from_u64` and `from_seed`;
  - the non-cryptographic generators in `rand`, `rand_pcg` and `rand_xorshift`.

  Each path was checked against the crate's source on 2026-11-01.

**Evidence.**
- **Unit tests:** 14 of 14, including:
  - every single-bit flip of a sealed message is refused (denominator asserted);
  - the RFC 8032 section 7.1 test vector, checked against the RFC text;
  - each floor line passes at its value and is refused one iteration below it.
- **Mutations** (each control disabled in turn, tests re-run): 9 of 9 caught.

  A tenth control, a 256-byte bound on stored hashes, was removed instead: no test could make it fire, because the PHC parser already holds every field in a fixed-size buffer, and the bound would have refused a valid maximum-size hash.
- **Bans, on Linux** (`cargo corten check` with the example policy plus the 19 admitted packages):
  - 24 of 24 fire, each with its own `use of a disallowed type` or `method` diagnostic;
  - the same programs pass with the same admissions and no bans;
  - a benign program passes with the bans.
- **CI** (run 41356524543, Linux):
  - nextest: 202 of 202 passed;
  - corpus: 169 of 169 detected, 0 of 169 falsely rejected;
  - hermetic smoke test: 3 of 3;
  - `cargo deny`: passes with 23 more packages in the lockfile (56 to 79).
- **A defect caught on the way.** The first CI run falsely rejected 83 of 169. An exported `password::meets_floor(u32, u32)` broke the driver's labelled-parameters lint, and `corten-std` must pass its own profile, so every case that uses it failed to build. The function is now private.

**Not done in this batch:**
- Corpus cases for the strategy 10 CWEs. These come before any E claim; the strategy only says "E candidate for prelude users".
- Key derivation (HKDF) and key agreement (X25519).
- Strategy 7.

## Findings of 2026-11-02, outside the network design

Found while reviewing the components that exist with the questions asked of `NetCap`: trust anchors, rotation, transport integrity and failure handling. Network attack vectors and their CWEs are in [`../netcap.md`](../netcap.md) section 5.

Each CWE is quoted from the ledger and is C today. The ledger changes only when a mitigation is built and tested (`netcap.md` section 6). Each row is an item with a status, so it is not lost.

| # | Finding | Evidence | CWEs (ledger) | Mitigation plan | Status |
| --- | --- | --- | --- | --- | --- |
| F1 | The signed manifest has no expiry, no serial and no key identifier, so an older validly signed manifest that granted more can be replayed, and the signing key cannot be rotated without replacing every verifier | `crates/corten-std/src/manifest.rs` checks one Ed25519 signature against one key; 0 matches for expiry, serial, rollback, replay or key-ID terms (control: 6 for `ed25519`); `spec.md` and `tcb.md` do not mention manifest replay | 294 Authentication Bypass by Capture-replay; 324 Use of a Key Past its Expiration Date | Add `not-after`, a monotonic `serial` checked against a persisted high-water mark, and a key identifier with a key set; refuse on any failure, logged | Built (2026-11-02): manifest format 2 with `key`, `serial` and `not-after`; `TrustedKeys`; `corten-sandbox --trusted-key ID=HEX --serial-state FILE`. Tests: `corten-std` manifest 10 of 10, mutations 5 of 5 caught; a tautological key-line check that no test could make fire was removed. Linux sandbox results in the pull request. Ledger rows 294 and 324 change when this lands (`netcap.md` section 6) |
| F2 | A confined program can send UDP anywhere: Landlock ABI v4 governs files and TCP only. This is also the path DNS exfiltration would take from a sandboxed resolver | `docs/tcb.md`, "What a confined program can still reach" | 923 Improper Restriction of Communication Channel to Intended Endpoints; 668 Exposure of Resource to Wrong Sphere | A confined program without a network grant runs in an empty network namespace (`rustix::thread::unshare` with `NEWNET`, a safe API). Not measured: an unprivileged namespace may also need a user namespace, which some distributions disable. Measure, then fail closed where it is unavailable | Planned (batch 5, with strategy 7) |
| F3 | `corten_std::crypto` has no key rotation. A sealed message names a format but not a key; `password::verify` cannot say "rehash: weaker than current"; `verify_signed` takes one key | `crates/corten-std/src/crypto.rs` (Phase 6, batch 5) | 324 Use of a Key Past its Expiration Date; 916 Use of Password Hash With Insufficient Computational Effort; 347 Improper Verification of Cryptographic Signature | Format version 2 with a key identifier and a keyring for opening; `password::verify` returns whether the hash is below the current parameters; `verify_signed` over a key set with identifiers | Planned (batch 5 follow-up) |
| F4 | The Layer 4 action's provenance is unsigned by design ("sign it with an attestation step"). Not checked yet: whether anything verifies a signed provenance before deployment (Layer 5) | `action.yml` lines 35 and 77 | 347 Improper Verification of Cryptographic Signature; 494 Download of Code Without Integrity Check; 353 Missing Support for Integrity Check | First read what Layer 5 checks. If nothing verifies the signature, add verification to the deployment check, refusing unsigned or unverifiable provenance | To verify |
| F5 | The hermetic build's only networked step (`cargo vendor`, outside the sandbox) was not re-checked for integrity | `crates/cargo-corten/README.md`, "Hermetic build" | 494 Download of Code Without Integrity Check | Measured 2026-11-02: a dependency's build script could rewrite another dependency's vendored source inside the sandbox, with or without its checksum entry, and the build used the rewritten code. Fix: vendored sources and their configuration in a private directory outside `target/`, read-only in the sandbox; `CARGO_HOME` emptied before each pass. Smoke case 4: the rewrite is refused (`PermissionDenied`, original code built) after a plain-cargo control where it succeeds; with `main`'s checker, case 4 fails | Fixed (2026-11-02) |

## Batch 5, strategy 7: `NetCap` core (2026-11-02)

`corten_std::net` (design in [`../netcap.md`](../netcap.md)).
- **Grant:** a manifest line `net NAME HOST:PORT [private]`, taken with `Capabilities::take_net`.
- **Connecting:** `NetCap::connect_tls` checks every address first:
  - IPv4-mapped addresses are canonicalized;
  - loopback, private, shared, link-local and metadata, unique-local, multicast, NAT64 and 6to4 addresses are refused unless `private`;
  - one refused address refuses all.
- **Timeouts:** the connection uses rustix with a bounded connect timeout and read and write timeouts (defaults 10 s and 30 s, ceiling 300 s).
- **TLS:** 1.3 only on `aws-lc-rs` with the platform's roots. Revocation is operator CRLs enforced including their expiry, or `Revocation::Unchecked`, which is logged as a warning (question 18).
- **Logging:** every connection writes `net.connect` (or `net.refused`) to the caller's `LogWriter` before data flows.
- **Sandbox:** `corten-sandbox` turns a `net` grant into a Landlock TCP connect rule for its port.
- **Not built:** name resolution. A host grant returns `NoResolver`. No ledger row moves until the strategy is complete (`netcap.md` section 6).

**Evidence.**
- **macOS:** `corten-std` net and manifest tests, 17 of 17.
- **Linux** (`rust:1.99.1-slim-bookworm`, `--rm` container):
  - Clippy clean, which covers the rustix socket code;
  - `corten-std` 22 of 22, including five handshakes against a local rustls server: TLS 1.3 round trip with the log record; a TLS 1.2-only server refused, with TLS 1.2 compiled into the test build so the configuration is what refuses it; a certificate for another address refused; a CRL listing the leaf refuses it, a CRL listing another serial accepts it with no warning, an expired CRL fails the connection; a closed port fails within the budget;
  - `corten-sandbox` 4 and 11.
- **Mutations on Linux:** 8 of 8 caught by failing tests: TLS 1.2 allowed, CRLs ignored, CRL expiry not enforced, address check bypassed, IPv4-mapped not canonicalized, metadata not refused, `Unchecked` not warned, refusal not logged. One mutant was first written so that it did not compile; re-run as a compiling mutant, it is caught.
- **Profile:** `corten-std` passes its own profile under `cargo corten check`.
- **Dependencies:** `cargo deny` passes; the lockfile grows from 79 to 134 packages.

## Batch 5, strategy 7: name resolution and DNS logging (2026-11-02)

`corten_std::net`, Linux. Host grants resolve with `hickory-resolver` 0.26.3 on a current-thread tokio runtime, bounded by the connect timeout, with at most 16 addresses kept.
- **Logging:** every change of DNS state writes `net.dns` (source, transport, DNSSEC status, fallback), and a `net.warning` when the answers are plain or not validated (`netcap.md` section 3).
- **DNSSEC status:** taken from resolving `dnssec-failed.org`, where SERVFAIL means validating.
- **Fallback:** Cloudflare or Google is probed with the test name only. The program switches to it over DNS over TLS only with `dns fallback NAME` in the manifest (question 16).
- **Sandbox:** `corten-sandbox` grants TCP 53 for host grants (the system resolver's TCP fallback) and 853 with `dns fallback`.
- **Dependency policy:** `deny.toml` skips `core-foundation` 0.9.4 (hickory's macOS system-config reader; `corten-std` uses hickory on Linux only).
- **Example policy:** `docs/dep-policy.example` bans `hickory_resolver::TlsConfig::insecure_skip_verify`. The path was checked against hickory's source; unlike the 24 bans of batch 5, it was not shown to fire.

**Found while building.** hickory's DNS-over-TLS client starts from an empty root store unless `webpki-roots` or `rustls-platform-verifier` is enabled, and both are refused by the licence policy (CDLA-Permissive-2.0). The first live run showed `fallback="probed-unavailable"` even with the opt-in. The resolver now uses `NetCap`'s TLS configuration (the platform's roots, TLS 1.3).

**Evidence.**
- **Linux** (`--rm` container):
  - Clippy clean;
  - `corten-std` 25 of 25 net and manifest tests (one live test ignored by default);
  - `corten-sandbox` 4 and 11.
- **Live DNS** (run by hand with `--ignored`; `example.com`, 4 addresses each time):
  - without opt-in: `net.dns source="system" transport="udp-tcp" dnssec="validating" fallback="probed-available"`, followed by the warning;
  - with `dns fallback cloudflare`: `source="cloudflare" transport="dot" dnssec="validating" fallback="switched"`, with no warning.
- **Mutation:** switching without the opt-in is caught by `the_public_resolver_is_used_only_by_opt_in`. The mutant compiled; the test failed with its message.
- **Dependencies:** `cargo deny` passes; the lockfile grows from 134 to 238 packages (hickory, tokio).
- **Not run here:** the corpus. CI runs it.

## Remaining work (recorded 2026-11-02)

Every open Phase 6 item, with what starts it. Design principles: AGENTS.md. Status lives here; the CHANGELOG and README summarise it.

| Item | Status | Trigger or next step |
| --- | --- | --- |
| E claims, question 21 | **Done** (2026-11-02, below): CWE-918, 319, 1428 E and verified; CWE-323, 916, 759, 760, 347 E, `review = required` | The crypto rows: the independent review (next row) |
| Independent review of the encoders (25 rows) and of `corten_std::crypto` (the five question 21 rows) | Blocked | The owner names a reviewer who is not the author (AGENTS.md rule 1) |
| F5: a dependency's build script could rewrite another dependency's vendored source inside `cargo corten build` | **Fixed** (2026-11-02): vendored sources read-only outside `target/`; `CARGO_HOME` emptied per pass; smoke case 4, with a plain-cargo control | — |
| Manifest signing helper (`cargo corten manifest sign`: bumps the serial, sets a default expiry), design principle 10 | Not started | After F5 |
| F3: key rotation in `corten_std::crypto` (key identifiers in sealed messages, rehash signal, verifying key set) | Not started | After the signing helper |
| F2: UDP from confined programs (empty network namespace through `rustix::thread::unshare`) | Not started | After F3; measure unprivileged user namespaces in the container and on GitHub's runners first |
| F4: nothing verifies the Layer 4 provenance before deployment. Checked 2026-11-02: `action.yml` outputs an unsigned in-toto statement ("sign it with an attestation step") and no step signs or verifies it; `provenance`, `attest`, `in-toto` and `slsa` occur in 0 files of `crates/corten-sandbox` and `crates/corten-std/src` (the same search finds `scripts/hermetic-smoke.sh` and the README). Layer 5 starts any binary it is given | Gap confirmed | Owner decision: how a deployment binds the binary it runs to the build that checked it |
| Resolver out of process (question 20, option C): hickory and tokio leave every program's address space | Deferred: an isolation improvement, not a fix | When strategy 7 is revisited, or if a hickory advisory affects the resolver path |
| DNSSEC validation inside the prelude; DNS over HTTPS; Happy Eyeballs | Not built (`netcap.md` status) | DNSSEC: measured before enabling (question 17). The others when a deployment needs them |
| `hickory_resolver::TlsConfig::insecure_skip_verify` ban in `docs/dep-policy.example` | Path checked, not shown to fire | With the next dependency-policy change: add it to the firing test |
| CI: the cache does not measurably shorten the corpus step. Measured 2026-11-02 on `main`, with the cache restored: 24.8, 34.5, 27.7 and 18.9 minutes (pushes of `4b91041`, `359a2d5`, `242b1cb`, then the schedule), against 23.6 minutes (1,416 s) uncached; #24 (177 cases) took 27.4. The light path works: docs-only #23's `tests` job took 1.7 minutes with 9 steps skipped. **Why, measured locally (Linux container, 8 CPUs) on one corpus case:** a cold `cargo corten check` took 112 s and compiled 78 crates; a repeat took 2 s and compiled none, and still none after every source file was touched (as a fresh checkout does). So the cache can save only each worker's one cold build (about 2 minutes), while the step runs 308 checker invocations and 384 plain `cargo check` runs (177 cases, counted from the ledger's proof kinds and each variant's `//@ kind`) | Explained; nothing to fix in the cache | If the corpus must get faster: per-invocation cost (vendoring and the sandboxed passes per check), or sharding the step (sota-devsecops rules/16 §16.4) |
| Batch 2b: labels on errors, logs and debug output (strategy 9) | Not started | Needs an API design first; propose it against the design principles |
| Batch 3: budgets (strategy 4), safe deserialization and `ConfigCap` (strategy 3) | Not started | Strategy 3 needs a format and dependency review; strategy 4 changes every parsing entry point and needs a migration plan |
| Strategy 8, DirCap extensions | **Built** (2026-11-02; owner decisions: an explicit `FileMode` enum, opt-in single-link opens, an upload sink with a generated name and a declared type): `OpenMode::CreateExclusive(FileMode)` (0600, 0640 or 0644, set exactly with `fchmod`), `ReadSingleLink` and `AppendSingleLink` (`FsError::HardLink`), `DirCap::store_upload` with `DeclaredType`. The 31 rows stay C: a program can still choose a wider mode or a plain open. Moving any to E (question 21) needs its own corpus case | Corpus cases for the rows the new API makes inexpressible, then an E proposal per row |
| Batch 4: authorization proof types (strategy 2) | Not started | Prototype on the corpus; adopt only at 0 false rejections (question 14) |
| Batch 6: web types, credentials, strict parsers, contracts, runtime, supply chain | Not started | After batch 3 |

## E claims for the network and cryptography APIs (question 21, 2026-11-02)

Eight rows moved from C to E, prelude-only, each with a corpus case and a reason in the ledger.

**Network: CWE-918, 319 and 1428, verified by the corpus.**
- **Good program:** each case's `good.rs` takes a `NetCap` from the manifest and writes over TLS.
- **Bad variants:**
  - a caller-chosen `TcpStream` connection, a cleartext write, a plain HTTP request;
  - DNS through `ToSocketAddrs` (CWE-918);
  - a forged `NetCap`, refused because it has no public constructor (CWE-918);
  - UDP (CWE-319);
  - `curl` through `std::process`;
  - an HTTP client crate, and raw `rustix` (CWE-918), refused by the operator's dependency policy.

**Cryptography: CWE-323, 916, 759, 760 and 347, E with `review = required`,** so they stay unverified until an independent review of `corten_std::crypto`, as the encoder rows do.
- **Bad variants:**
  - a caller-chosen nonce (`seal` takes none, E0061);
  - a caller-chosen cost (the API has none: `absent`, the weakest evidence);
  - a caller-chosen salt (`hash` takes none, E0061);
  - unchecked data where `Verified<T>` is required (mismatched types), and a hand-made `Verified` (private field);
  - the raw crates directly: `chacha20poly1305`, `sha2`, `argon2`, `ed25519-dalek`, refused by the dependency policy.

**Evidence.**
- **Corpus on Linux** (`--mark-verified`, a `--rm` container): 177 of 177 detected, 0 of 177 falsely rejected. The run changed exactly three rows, CWE-918, 319 and 1428, to verified.
- **A false rejection caught on the way:** a first run falsely rejected CWE-347's own `good.rs`. Its `receive(body, sig: &[u8], key: &[u8])` broke the labelled-parameters lint; it now takes `SignatureBytes` and `VerifyingKey`.

**Totals** (`corten-ledger totals`):
- **All 944 rows:** E 177 / C 724 / O 26 / N 17; 146 of the 177 E rows verified, 31 awaiting review.
- **Written in Rust (787):** E 154 / C 607 / O 26.
- **Remaining:** 638 CWEs (30 claimed E, 582 C, 26 O). MITRE's 2025 Top 25 still remaining: 16 (CWE-918 left).

**Regeneration order matters.** `scripts/applicability-table.py` before `scripts/residual-map.py`, which reads the table. Run first, the map still said 641.
