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
| 3 | 4 budgets and timeouts; 3 safe deserialization and `ConfigCap`; 8 DirCap extensions | strategy 8 **built** (2026-11-02, remaining-work table), CWE-276, 689 and 708 E and verified (2026-11-06, below); 4 and 3 not started | |
| 4 | 2 authorization and authentication proof types: prototype, adopt only at 0 false rejections (question 14) | step 1 **built** (2026-11-13, below): `corten_std::authz`, manifest authenticators, protected directories; corpus cases not started | |
| 5 | 10 cryptography and randomness; 7 TLS and network capabilities (question 13) | strategy 10 **done** (2026-11-01, below): `corten_std::crypto`, `corten_std::random`, weak-primitive bans; strategy 7 **built** (2026-11-02, below): `NetCap` core, then resolution, DNS logging and the opt-in fallback ([`../netcap.md`](../netcap.md)) | |
| 6 | 6 web types; 11 credentials; 12 strict parsers; 13 contracts; 5 runtime; 14 supply chain | not started | |
| — | 1 the independent encoder review (26 ledger rows; 25 of them writable in Rust, CWE-564 is not) | blocked | An external audit being engaged (owner decision 2026-11-03, remaining-work table; AGENTS.md rule 1: not the encoders' author; the AI pre-review is not the review of record) |
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
| F2 | A confined program can send UDP anywhere: Landlock ABI v4 governs files and TCP only. This is also the path DNS exfiltration would take from a sandboxed resolver | `docs/tcb.md`, "What a confined program can still reach" | 923 Improper Restriction of Communication Channel to Intended Endpoints; 668 Exposure of Resource to Wrong Sphere | A confined program without a network grant runs in an empty network namespace (`rustix::thread::unshare` with `NEWNET`, a safe API). Not measured: an unprivileged namespace may also need a user namespace, which some distributions disable. Measure, then fail closed where it is unavailable | **Built** (2026-11-02): an empty network namespace for programs without a network grant (remaining-work table, F2) |
| F3 | `corten_std::crypto` has no key rotation. A sealed message names a format but not a key; `password::verify` cannot say "rehash: weaker than current"; `verify_signed` takes one key | `crates/corten-std/src/crypto.rs` (Phase 6, batch 5) | 324 Use of a Key Past its Expiration Date; 916 Use of Password Hash With Insufficient Computational Effort; 347 Improper Verification of Cryptographic Signature | Format version 2 with a key identifier and a keyring for opening; `password::verify` returns whether the hash is below the current parameters; `verify_signed` over a key set with identifiers | **Fixed** (2026-11-02, owner decision: caller-chosen 32-bit key identifiers, format 1 dropped): format 2 seals under a `KeyId` and authenticates the header; `KeyRing` seals with its current key, opens by the identifier a message names, flags messages to re-seal and retires old keys; `password::verify` returns `Check::Rehash` for a hash at other costs; `verify_signed` checks against `VerifyingKeys` by identifier |
| F4 | The Layer 4 action's provenance is unsigned by design ("sign it with an attestation step"). Not checked yet: whether anything verifies a signed provenance before deployment (Layer 5) | `action.yml` lines 35 and 77 | 347 Improper Verification of Cryptographic Signature; 494 Download of Code Without Integrity Check; 353 Missing Support for Integrity Check | First read what Layer 5 checks. If nothing verifies the signature, add verification to the deployment check, refusing unsigned or unverifiable provenance | **Fixed** (2026-11-02): the signed manifest pins the program's SHA-256 and `corten-sandbox` refuses any other binary (remaining-work table, F4) |
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
- **Example policy:** `docs/dep-policy.example` bans `hickory_resolver::TlsConfig::insecure_skip_verify`. The path was checked against hickory's source; unlike the 24 bans of batch 5, it was not shown to fire until 2026-11-04 (it fires: "Safe Rust through a crate" below).

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
| Independent review of the encoders (26 ledger rows with `review = required`; 25 of them writable in Rust, CWE-564 is not) and of `corten_std::crypto` (the five question 21 rows) | Blocked. **Owner decision 2026-11-03:** commission one external audit of the encoders and `corten_std::crypto` together, rather than naming an individual reviewer, so one engagement covers all 31 rows. Hand-over: `docs/gates/encoder-prereview.md`, `crates/corten-std/tests/encoder_properties.rs`, the corpus variants | The audit engaged; the auditor records a review link per row in the ledger's `review` column, then `corten-corpus --mark-verified` (AGENTS.md rule 1) |
| F5: a dependency's build script could rewrite another dependency's vendored source inside `cargo corten build` | **Fixed** (2026-11-02): vendored sources read-only outside `target/`; `CARGO_HOME` emptied per pass; smoke case 4, with a plain-cargo control | — |
| Manifest signing helper, design principle 10 | **Done** (2026-11-02; owner decisions: a 0600 key file, serial = Unix time, 90-day default expiry capped at 366): `corten-manifest keygen` and `corten-manifest sign`, a separate tool so the checker gains no signing code (principle 6; the tracker had named it `cargo corten manifest sign`). `sign` verifies its output with `corten_std::manifest::verify` before writing; 6 tests, and deleting the key-file mode check failed one | — |
| F3: key rotation in `corten_std::crypto` | **Done** (2026-11-02): see finding F3 above; 15 crypto unit tests pass, including a header-relabelling test shown to fail when the header is not authenticated | — |
| F2: UDP from confined programs | **Built** (2026-11-02; owner decision: refuse unless `--allow-udp-without-netns`): a program with no network grant runs in an empty network namespace inside a user namespace (`rustix::thread::unshare`). Measured in the container: unprivileged user and network namespaces work (`unshare --user --net` as `nobody`, rc 0, only `lo`). Measured on GitHub's Ubuntu 24.04 runner (#28, runs 41549857213 and 41588767789): `unshare` succeeds, writing `/proc/self/setgroups` fails with EACCES, so the ID maps are best effort (IDs show as 65534 inside); with that, 245 tests passed there, including `udp_is_refused_without_a_network_grant` | — |
| F4: nothing verified the Layer 4 provenance before deployment | **Fixed** (2026-11-02; owner decision: the digest in the signed manifest): manifest format 3 requires `program sha256 HEX`; `corten-sandbox` opens the program, hashes that open file and executes the same file through `/proc/self/fd`, refusing a mismatch before the serial is advanced; `corten-manifest sign --provenance` copies the digest from the build's statement | — |
| Resolver out of process (question 20, option C): hickory and tokio leave every program's address space | Deferred: an isolation improvement, not a fix | When strategy 7 is revisited, or if a hickory advisory affects the resolver path. Checked 2026-11-05, not fired: the RustSec database (fetched that day, 1,409 advisories) has five hickory advisories, none affecting the locked 0.26.3 (fixed by 0.26.1, unaffected from 0.26.0-beta.1, or against `hickory-recursor`, which is not in `Cargo.lock`); `cargo audit` and `cargo deny check advisories` pass. Re-checked 2026-11-09, not fired: 1,430 advisories in the RustSec database; `cargo audit` (240 crates in `Cargo.lock`) and `cargo deny check advisories` pass. Re-checked 2026-11-13, not fired: the RustSec database (fetched that day, 1,506 advisories) now has 34 hickory advisories, 29 of them added 2026-11-11 to 13; none affects the locked 0.26.3 (`hickory-net`, `hickory-proto` and `hickory-resolver` ones fixed by 0.26.2 or earlier; eight `hickory-proto` ones with no fix are unaffected from 0.26.0-beta.1; three against `hickory-recursor`, not in `Cargo.lock`); `cargo audit` 0.22.2 and `cargo deny` 0.20.2 `check advisories` pass |
| DNSSEC validation inside the prelude; DNS over HTTPS; Happy Eyeballs | Not built (`netcap.md` status) | All three when a deployment needs them (DNSSEC's trigger set by the owner 2026-11-13; it had only a precondition); DNSSEC is measured before it is enabled (question 17) |
| `hickory_resolver::TlsConfig::insecure_skip_verify` ban in `docs/dep-policy.example` | **Done** (2026-11-04): the trigger fired with the next policy change, and the ban fires under `cargo corten check` on Linux ("Safe Rust through a crate" below) | — |
| CI: the cache does not measurably shorten the corpus step. Measured 2026-11-02 on `main`, with the cache restored: 24.8, 34.5, 27.7 and 18.9 minutes (pushes of `4b91041`, `359a2d5`, `242b1cb`, then the schedule), against 23.6 minutes (1,416 s) uncached; #24 (177 cases) took 27.4. The light path works: docs-only #23's `tests` job took 1.7 minutes with 9 steps skipped. **Why, measured locally (Linux container, 8 CPUs) on one corpus case:** a cold `cargo corten check` took 112 s and compiled 78 crates; a repeat took 2 s and compiled none, and still none after every source file was touched (as a fresh checkout does). So the cache can save only each worker's one cold build (about 2 minutes), while the step runs 308 checker invocations and 384 plain `cargo check` runs (177 cases, counted from the ledger's proof kinds and each variant's `//@ kind`) | Explained; nothing to fix in the cache. **Per-invocation cost profiled (2026-11-07, Linux container, one warm worker, CWE-918's good program):** a checker run in a fresh case directory, as `corten-corpus` writes one (no `Cargo.lock`), took 3.13, 2.32 and 2.14 s, each updating the crates.io index and locking 194 packages; the same directory checked again, with the lock present, took 0.89 and 0.90 s. Order of work (exec trace): metadata with the index update, `cargo vendor` outside the sandbox, the sandboxed Clippy pass, the sandboxed `corten-driver` pass. So re-resolving per case costs about 1.2 to 2.2 s per checker run, roughly 370 to 680 worker-seconds over 308 checker runs, against about 7,800 worker-seconds in CI's step (1,961 s on 4 workers): most of the step is not located yet. *Superseded the same day by measurement:* CI counted 332 checker calls and 6,039.7 worker-seconds (run 42406090845; the 308 and 7,800 above were a 177-case count and an estimate), and the rest was located in the shared vendor directory (next column) | If the corpus must get faster: first, time each case inside `corten-corpus` and read CI's distribution (the unexplained part). **Built 2026-11-07:** `corten-corpus` prints a timing summary to standard error. First reading (phase 6, 2 workers, Linux container): checker calls are bimodal, median 0.21 s but p90 39.35 s and max 90.06 s, and four warm cases (CWE-689, 276, 319, 708, positions 1 to 5) still took 41 to 45 s each. CI's full run of this change (run 42406090845, 4 workers, 180 cases): 6,039.7 worker-seconds, of which `cargo corten check` 5,546.1 s over 332 calls (median 1.90 s, p90 70.84 s, max 84.03 s) and plain `cargo check` 492.9 s over 406 calls; the slowest warm cases were the path family (CWE-26, 27, 28, 30, 31 at queue positions 37 to 47, 84 to 87 s each, with no fake dependencies), so the first guess, fake-dependency source replacement, was retracted. **Cause of the slow calls, measured (2026-11-07, Linux container, fresh case directories sharing one target directory):** a `corten-std` check after another took 1.66 to 3.12 s (five runs); after a dependency-free check in between it took 28.87 to 31.76 s (four runs). The dependency-free check empties the worker's shared vendor directory (193 crates to 0, keyed by the target directory), and the next check re-vendors all 193 and rebuilds. The re-vendored files keep their archive timestamps, so which units cargo rebuilds, and why, is not established: `CARGO_LOG` did not reach the sandboxed cargo, whose environment the checker clears. **Fixed 2026-11-07 (owner decision: option 1, the corpus only, no change to the checker):** `corten-corpus` gives each case crate a target directory per worker and dependency set (`deps-none`, `deps-std`, `deps-nix`, ...; 13 sets in the 586 corpus files, only `std` needs the large build), so the corpus no longer empties a vendor directory. Phase 6, 2 workers, Linux container, from a cold work directory: before 241 and 255 s wall (worker-seconds in the checker 390.2, p90 44.86 s), after 155 s (checker 208.8, p90 2.55 s). One of three before runs failed CWE-918's plain control in rustup (a concurrent first download of `rust-src` in a fresh container), not in the corpus code; **CI, full corpus (4 workers):** run 42406090845 (before) against 42420546715 (after): the corpus step 1,522 s to 566 s; worker-seconds 6,039.7 to 2,252.9; checker 5,546.1 to 1,446.8 s (p90 70.84 to 3.35 s); 180 of 180 detected and 0 of 180 falsely rejected in both. The after run started cold for the new `deps-*` directories (the cache, written by `main`, had the old layout: first cases 259 to 394 s, plain calls 492.9 to 805.6 s), so later runs on `main` were expected to be faster still. **Measured 2026-11-09: they were not, because the cache never took the new layout.** The next three `main` runs (42422911164, 42423967314 and the schedule's 42629047981) took 542, 529 and 526 s in the corpus step, and the schedule's cold first cases were still 264, 388 and 391 s on three of four workers (259, 391 and 394 s in 42420546715). Each run restored `v0-rust-test-Linux-x64-bde586ff-0496dd70` as a full match, and its post step printed `Cache up-to-date.`: rust-cache does not save after an exact match, and its automatic key hashes Cargo files and toolchains, not the corpus layout. **Fixed 2026-11-09:** the `tests` job's cache `key` hashes `crates/corten-corpus/src/**`, so a layout change re-saves the cache; the first `main` run after the merge saves it, and the run after that should show the cold first cases gone. **Measured 2026-11-10** on `main` run 42720424732 (the merge of #46), which restored the new key as a full match: corpus step 239 s (526 to 566 s before), 944.3 worker-seconds (2,095.7 to 2,252.9), the three cold first cases 91 to 96 s (259 to 426 s); 180 of 180 detected, 0 of 180 falsely rejected. The first cases still compile some dependencies (about 90 s), which is not investigated. Then one per-worker `Cargo.lock` copied into each case directory would remove the per-case index update and locking (also a network round trip per check). Then sharding (sota-devsecops rules/16 §16.4) |
| Batch 2b: labels on errors, logs and debug output (strategy 9) | Not started | Needs an API design first; propose it against the design principles |
| Batch 3: budgets (strategy 4), safe deserialization and `ConfigCap` (strategy 3) | Not started | Strategy 3 needs a format and dependency review; strategy 4 changes every parsing entry point and needs a migration plan |
| Strategy 8, DirCap extensions | **Built** (2026-11-02; owner decisions: an explicit `FileMode` enum, opt-in single-link opens, an upload sink with a generated name and a declared type): `OpenMode::CreateExclusive(FileMode)` (0600, 0640 or 0644, set exactly with `fchmod`), `ReadSingleLink` and `AppendSingleLink` (`FsError::HardLink`), `DirCap::store_upload` with `DeclaredType`. The 31 rows stay C: a program can still choose a wider mode or a plain open. Moving any to E (question 21) needs its own corpus case. Tested under `umask 077` (2026-11-03, Linux container): `fs::tests::creation_modes_are_exact_under_umask_077` runs a child test process with that umask, whose plain create of 0644 gets 0600 (the control), and finds 0600, 0640 and 0644 exact; with the `fchmod` call removed it fails (0600 for 0640) while the default-umask test still passes | **E claims done (2026-11-06)** for CWE-276, 689 and 708 ("Strategy 8 E claims" below); the other 28 rows stay C, each with a reason ([`fs-caps-e-proposal.md`](fs-caps-e-proposal.md)). CWE-62 and CWE-434 decided 2026-11-06 (questions 2 and 3 there): both stay C; CWE-62's sandbox check is the next row |
| `corten-sandbox` requires `fs.protected_hardlinks = 1` (CWE-62, owner decision 2026-11-06, option D of `fs-caps-e-proposal.md`): refuse to start otherwise, unless the operator passes an explicit opt-out, which is warned on every start | **Built** (2026-11-07): checked before Landlock; a value other than 1 or a failed read exits 3, and `--allow-unprotected-hardlinks` runs with a warning on every start. `cargo corten` and `corten-broker` pass no opt-out. Test `unprotected_hard_links_refuse_unless_the_operator_opts_out` covers the decision, and a mutant accepting anything but `0` fails it. Fired end to end (Linux container, 2026-11-07), with a file holding `0` bind-mounted over `/proc/sys/fs/protected_hardlinks` in a private user and mount namespace (the host value stayed 1): the default run exits 3 with its message, the opt-out run exits 0 with the warning. With the host at 1: Clippy clean, `corten-sandbox` 7 unit and 13 broker tests, `cargo-corten` tests, hermetic smoke test, and a direct run with no warning. Not automated: the namespace probe needs `unshare` and `mount`, so it is a recorded manual check | CWE-62 stays C (it rests on a kernel setting) |
| Batch 4: authorization proof types (strategy 2) | Not started. **Next strategy (owner decision 2026-11-10)**, ahead of budgets, labels and deserialization, and ahead of the prebuilt driver (owner decision 2026-11-13, that row): next in the accepted proposal's order, and it covers 4 of the 16 remaining Top 25 (CWE-862, 863, 639, 306) and KEV CWE-306 and 288 | Design note 2026-11-10 ([`authz-proposal.md`](authz-proposal.md)); **owner decisions the same day, the recommendation on both:** a proof is required by grants the signed manifest marks `protected` (Q1), and only prelude authenticators the manifest names construct a principal (Q2). Next: the corpus prototype; adopt only at 0 false rejections (question 14). Cedar is weighed after the prototype |
| Capabilities the spec's MVP lists that `corten-std` lacks: a clock, listening sockets, UDP and Unix sockets. The checker bans `SystemTime::now`, `Instant::now`, `TcpListener`, `UdpSocket` and the Unix-socket types, so a checked program cannot read the time or accept a connection through `std` or `corten-std` (`corten-std` has no public time API; a crate the operator admits could still offer one). Found 2026-11-10 while writing the ban reasons (the clock ban's reason had said "use a clock capability", which does not exist); no row tracked it | Not started; needs an API design (a manifest grant for each) | With batch 6 (the web types need a listener), or earlier when a corpus case or a caller needs one |
| Batch 6: web types, credentials, strict parsers, contracts, runtime, supply chain | Not started | After batch 3. Candidate with the web types: a `served` flag on manifest `dir` grants, whose `DirCap` accepts only `store_upload` (CWE-434 option B, `fs-caps-e-proposal.md`; CWE-434 stays C until labels, strategy 9, owner decision 2026-11-06) |
| Key derivation (HKDF) and key agreement (X25519) in `corten_std::crypto`. Listed as not done in strategy 10's result (2026-11-01) but had no row here until 2026-11-05 | Not started | With batch 6, credentials (strategy 11), or earlier when a corpus case or a caller needs derived or agreed keys (owner decision 2026-11-05) |
| Spec section 5: every explicit wipe observable (CWE-14, 244, 733; ledger strategy `secrets`) | Not started; part of strategy 11 (`../residual-mitigation.md`) | With batch 6 (credentials) |
| Spec section 5: secret spill control (CWE-316; ledger strategy `secrets`) | Partly done (Phase 2): `Secret<T>` is `mlock`ed and the process non-dumpable on Linux. **Deferred (owner decision 2026-11-04)** for per-page `MADV_DONTDUMP`: the process-wide non-dumpable flag (`secret.rs`, `set_dumpable_behavior(NotDumpable)`, with a test) already keeps the process out of core dumps, so a per-page flag would add protection only to a dumpable process. memmap2 0.9 offers it with no `unsafe` on an anonymous mapping it owns (`MmapMut::map_anon`, then `advise(Advice::DontDump)`; memmap2 0.9.12, MIT OR Apache-2.0, depends on libc and stable_deref_trait), but adopting it adds a dependency to the trusted base (principle 6), costs at least one locked page per secret (`Secret<T>` is a `region`-locked `Box<[u8]>` today), so programs reach the locked-memory limit sooner (creation already fails closed when the lock fails), for a debuggability gain rather than a CWE-316 one. The flag holds whatever `fs.suid_dumpable` says: the kernel skips the dump when the task's dumpable state is off at dump time, which is what `prctl` sets (`coredump_skip` in `fs/coredump.c`, read on Linux `master` 2026-11-04). Register and stack spills stay blocked: no LLVM attribute forbids spilling, and neither option touches them | Per-page no-dump: an operator needs core dumps of a Corten program; then review memmap2 against `deny.toml` and design a page-backed `Secret<T>` with its per-secret memory cost stated. Spills: an LLVM attribute that forbids them |
| Spec section 5: arithmetic ergonomics, a `strict_math!` block instead of `checked_add` chains (CWE-190, 191; ledger strategy `contracts`) | Not started; needs an API design (a macro that propagates `?` through `+`, `-`, `*`) | With batch 6 (contracts, strategy 13); propose against design principle 1 |

### Developer friction (proposal reviewed 2026-11-03)

From an external proposal, "Corten: Reducing Developer Friction". Its goal: keep the guarantees while making Corten something developers choose. The owner accepted it as backlog on 2026-11-03; nothing is decided yet. Rows marked "decision" need an owner choice first, proposed against the design principles in `AGENTS.md`.

**Already true when reviewed:**
- **Signed manifests** (its friction point 5): mostly addressed by `corten-manifest` (#27): `keygen`; and `sign`, which takes the serial from the clock, defaults to 90-day expiry and copies the program digest from the provenance.
- **Cross-platform** (its point 6): harder since F2 (#28, Linux network namespace) and F4 (#27, executing the checked file through `/proc/self/fd`). A macOS or Windows backend must match both, or the ledger must record the gap per platform.

**Corrections to the proposal, checked 2026-11-03:**
- **Corpus:** 177 cases, not 174 (`corpus-report.md`).
- **birdcage:** latest release 0.8.1 (2024-04-19) has no Landlock dependency. On Linux it uses namespaces and seccomp; "landlock" appears in 1 of its 48 files, as syscall numbers in its seccomp list. Its repository is archived, and its licence is GPL-3.0-or-later (crates.io and GitHub).
- **Codex CLI:** the `openai/codex` repository is Apache-2.0 (GitHub API). Check each file's header before reuse.

| Item | Status | Trigger or next step |
| --- | --- | --- |
| Prebuilt `corten-driver` (signed binary or dev container), so developers never handle the nightly pin | Not started. **Decided 2026-11-10 (owner, the recommendation):** CI builds the driver per platform on the pinned nightly, and `cargo-corten`'s source pins each binary's SHA-256 (`corten-sha256`, no new dependency), refusing any other; signatures and provenance from the layer 4 pieces. Rejected: a dev container image (trusts the registry, and nothing for native macOS) and building locally (keeps the nightly on every developer). **Distribution decided the same day:** release assets on the owner's signed `v*` tags (rejected: CI artifacts, which expire and are tied to no signed tag; deferring). **Pinning decided 2026-11-13 (owner, the recommendation):** a digest pinned in the tagged commit cannot name a binary built from that same commit, so the pin lands in a following commit that changes only the pin file, and the signed `v*` tag goes on that commit, signing the source and the pin together. Rejected for now: a reproducible build first (cost unmeasured on a nightly rustc driver per platform); kept as later hardening | **After batch 4 (owner decision 2026-11-13, the recommendation; the question was raised 2026-11-11):** batch 4 goes first because it carries the Top 25 work, and the drafted announcement inviting trials waits for this driver, which still comes before any external user trial. Rejected: the driver first (batch 4 slips), and announcing without it (breaks this row's own precondition) |
| Starter tier: warn-only, stable-only entry point, stricter tiers enabled one at a time | Not started; **decision**. It must say plainly that it verifies nothing. The driver is what holds code to stable's feature gates (question 22) and runs the lints, so a silent warn-only mode would be a bypass | With the prebuilt driver |
| Errors that teach: every rejection names the CWE, one line of why, the exact fix; `cargo corten fix` for machine-applicable fixes | **Slice 1 done** (2026-11-10): each of the checker's 77 bans gives the weakness with its CWE and the fix (`profile.rs`; the CWE from the ledger or the corpus case that uses the API; 11 bans with no ledger row say so, and those whose capability `corten-std` lacks say that instead of naming a fix); after a refused pass, the checker explains every forbidden lint whose `-F` note appeared, rustc, Clippy and `corten-driver` alike (`explain.rs`; a test fails when a forbidden lint has no entry). Measured on macOS: a matcher mutant fails 1 unit and 2 end-to-end tests. The corpus's 61 distinct `expect` strings were checked against the new text: the only overlaps are words already in the lint's own note | Next: `cargo corten fix` for the machine-applicable cases (`as` to `From`/`TryFrom`, `+` to `checked_add`); compile errors that are not lints (E0061, private constructors) are not explained yet |
| Metric: time to first passing check, per supported OS, tracked beside the 5% false-rejection limit | **Linux measured** (2026-11-05): **141 s and 102 s** (two runs) from a fresh clone of `main` at `59ce90d` to a passing `cargo corten check` of a new `cargo new` crate with no dependencies, in a `--rm` `rust:1.99.1-slim-bookworm` container (8 CPUs, kernel 6.17.7, Landlock available). Steps, run 1 / run 2: install `git` 7 / 6 s; clone 1 / 1 s; `cargo install --path crates/cargo-corten` 8 / 7 s; `cargo install --path crates/corten-sandbox` 64 / 59 s; `scripts/build-driver.sh`, which downloads the pinned nightly with `rustc-dev`, 60 / 28 s; the check itself under 1 s, sandboxed (no warning; on Linux the checker refuses without `corten-sandbox`). Control, same container: an `unsafe` block and a `std::fs::read` call were each refused (exit 1, their own diagnostics). Not counted: the image already holds Rust 1.99.1 and rustup; a crate with dependencies also needs a dependency policy and a cold build (112 s for one corpus case, CI row above). Seen on the way: the path is pieced together from `crates/cargo-corten/README.md` (install, `CORTEN_DRIVER`, the sandbox beside the checker); the top-level README had no quick start (added 2026-11-09). **macOS measured** (2026-11-09): **19 s and 14 s** (two runs) from a fresh clone of `main` at `51330ec` to a passing check, on macOS 26.7.2 (Intel i5-10600, 12 threads). Steps, run 1 / run 2: clone 3 / 2 s; `cargo install --path crates/cargo-corten` 6 / 4 s; `scripts/build-driver.sh` 7 / 6 s; the check 2 / 2 s, with the warning that build scripts and procedural macros run unsandboxed (no `corten-sandbox` off Linux). Not comparable with Linux: the pinned nightly and Rust 1.99.1 were already installed, so no toolchain download is counted. Control: an `unsafe` block and a `std::fs::read` call were each refused (exit 1, their own diagnostics). **Found on the way:** with the machine's default stable, rustc 1.97.1, the same `cargo new` crate is falsely rejected (next row) | Windows when a backend exists; re-measure after the prebuilt driver |
| `cargo corten check` falsely rejects every binary crate on rustc 1.97.1 (found 2026-11-09): the test target of `cargo new`'s hello world fails with E0453, `allow(dead_code) incompatible with previous forbid` (`-F dead_code`, strategy 15), and passes with the same `cargo-corten` and driver on rustc 1.99.1, the version the repository and the Linux image pin. Boundary measured the same day: 1.97.1 rejects, 1.98.0 and 1.99.1 accept | **Fixed** (2026-11-09; owner decision: option 1 of three, refuse below a measured minimum; rejected: dropping `-F dead_code` from test targets, which weakens strategy 15, and documenting the minimum only, which leaves the false rejection unexplained): the checker runs `rustc -vV` and exits 2 below 1.98.0, or when the release cannot be read, naming the minimum. Tests: 3 unit tests (`rustc_older_than_the_minimum_is_refused`, a nightly of 1.98.0 included) and `rustc_older_than_the_minimum_is_refused_before_checking`, end to end with a fake rustc and a 1.98.0 control; disabling the comparison fails both. On the real toolchains: 1.97.1 exit 2 with the message, 1.98.0 and 1.99.1 pass | — |
| Pre-approved crate list for the dependency policy | Not started | With the prebuilt driver, before any external user trial (trigger set by the owner 2026-11-13; the row had none). Each crate goes through the Phase 5 licence and supply-chain review; start with the crates the corpus and examples need |
| Migration tool: report how far a crate is from Corten, rewrite mechanical parts (direct `std::fs` into `DirCap`) | Not started | After `cargo corten fix` (errors that teach, slice 2; it reuses those fixes). Not fired by slice 1 (2026-11-10), which added messages, not fixes |
| Familiar APIs in `corten-std`: wrappers shaped like popular crates | Not started | With batch 6 (web types), crate by crate |
| Gradual adoption: one crate or module at a time in a workspace | Not started; needs a design (how the checker scopes the profile and the dependency policy per crate) | After the starter tier |
| IDE and coding-agent support: lints live through rust-analyzer; agent instructions or a skill for Corten-compliant code | Not started | Third in the proposal's order |
| Learning mode: record what a program accesses, draft a policy | Not started; **decision** (design note first). Guardrails from the proposal: output is a reviewed diff, never auto-applied; flag wide grants (wildcard hosts, home directory, credential stores); never in release builds or with signed manifests (consistent with question 9 and F4) | Fourth in the proposal's order; needs a per-OS way to observe denied accesses |
| Cross-platform sandbox layer: one Corten interface, per-OS backends (Landlock with namespaces on Linux, Seatbelt on macOS, AppContainer with restricted tokens and job objects on Windows) | Not started; **decision** (design note). The ledger records what is verified on each platform. Risks: `sandbox-exec` is deprecated (its man page says so on macOS 26.7.2, pointing to App Sandbox); the proposal also says the Seatbelt profile language is undocumented (not verified here); Windows is the largest effort | Fifth in the proposal's order: design note, then macOS, then Windows |
| Logic-bug methods: typestate and property tests as the default style; formal verification (Kani, Verus, Prusti) for critical code; TLA+, Loom or Shuttle for concurrency | Not started. Typestate and property tests need no decision | When the next strategy is designed, write it in typestate where protocol order matters |
| Authorization as an analysable policy language (Cedar) | Not started; timing decided (next column). It adds a dependency (principle 6), and batch 4 already plans authorization proof types (question 14) | After batch 4's prototype (owner decision 2026-11-13 on `authz-proposal.md` Q3, the recommendation; this row had said "before either starts", against the batch 4 row): weigh it against the measured prototype |

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

## Strategy 8 E claims (2026-11-06)

Owner decision 2026-11-06: the three E candidates of [`fs-caps-e-proposal.md`](fs-caps-e-proposal.md) go ahead. CWE-276, 689 and 708 move from C to E, prelude-only, and keep their strategy.

- **Ban-list gap closed.** `std::os::unix::fs::fchown` joins the checker's banned methods (`crates/cargo-corten/src/profile.rs`); `chown` and `lchown` already were. Watched on a probe calling `fchown(std::io::stdout(), ...)`: rc 0 before the ban, rc 1 with `use of a disallowed method std::os::unix::fs::fchown` after (macOS checker build).
- **Corpus cases** (`corpus/CWE-276`, `689`, `708`), each with a `good.rs` creating a file through `DirCap`:
  - CWE-276: `File::create`; `OpenOptions` with mode 0666; `set_permissions`; `DirBuilder` with 0777; a `FileMode` from bits (`absent`); `rustix` and `nix` (dependency policy);
  - CWE-689: `std::fs::copy` then `set_permissions`; create, write, then restrict; `rustix` and `nix`;
  - CWE-708: `chown`, `lchown`, `fchown` on standard output; `rustix` and `nix`.
- **ACL test.** `fs::tests::an_inherited_default_acl_grants_no_write_beyond_the_mode` sets a default ACL granting uid 65534 `rwx` and reads back each new file's ACL mask: 0 for 0600, `r` for 0640 and 0644. Its control is a plain create at 0666, which inherits the named user with write. Mutation: `OwnerWriteGroupRead` as 0660 fails it (mask 6, want 4). A filesystem without ACLs fails the test rather than skipping it.

**Evidence (Linux, `--rm` `rust:1.99.1-slim-bookworm` containers):**
- Clippy `-D warnings` on the workspace: clean.
- `corten-std` fs tests: 13 passed, 1 ignored (the umask child, run by its parent test).
- `cargo-corten` ban-list tests: 3 of 3, including `ban_list_resolves_and_safe_program_is_clean`, so the new path resolves.
- Corpus, phase 6, `--mark-verified`: 11 of 11 detected, 0 of 11 falsely rejected, 0 broken; the run set CWE-276, 689 and 708 to verified.
- Corpus, all phases (`docs/gates/corpus-report.md` regenerated): 180 of 180 detected, 0 of 180 falsely rejected, 0 failed controls, 0 broken.

**Totals** (`corten-ledger totals`): E 180 / C 721 / O 26 / N 17; 149 of the 180 E rows verified, 31 awaiting the external audit. Written in Rust (787): E 157 / C 604 / O 26. Remaining under Rust and Corten: 635 (`scripts/applicability-table.py`).

## Batch 4, step 1: proof types, authenticators and protected directories (2026-11-13)

Design: [`authz-proposal.md`](authz-proposal.md). No ledger row moves: the E candidates need corpus cases and a full corpus run at 0 false rejections first (question 14).

**Owner decisions (2026-11-13):**
- **Authenticators: signed tokens and a manifest password store** (recommended: tokens only, passwords later). Q2 said a program cannot mint a principal, but `crypto::password::hash` and `PasswordHash::from_stored` accept whatever the program supplies, so a password check over program-held hashes would let it mint any principal. The password store is therefore a file the manifest names and the program cannot write. The owner gave no reason for choosing it over tokens only.
- **Token format: Corten's own** (the recommendation; rejected: PASETO `v4.public` through `pasetors` 0.8.1, which adds `orion`, `serde_json`, `time` and `regex`, and JWT through `jsonwebtoken` 11.1.0). One line, `corten-token-1.KEY.AUDIENCE.SUBJECT.NOTAFTER.SIG`, an Ed25519 signature over everything before the last `.`, with no algorithm field: the same pattern as the signed manifest, and a documented departure from "no hand-rolled token formats" in exchange for no new dependency (design principle 6).
- **CWE-566 stays on the chart as planned** (recommended: drop it from the chart). The prototype cannot cover it: `corten-std` has no database capability (`sql.rs` is an encoder), so nothing makes an SQL lookup take its key from a proof. It waits for a database capability, which no scheduled item builds yet. The owner gave no reason.

**Built:**
- **`corten_std::authz`.**
  - `Authenticated` and `Authorized<A, K>` have private fields and no public constructor. `Authorized` is not `Clone`, and each protected operation consumes one.
  - `check(who, action, key, policy, log)` asks the program's `Policy` and logs `authz.allowed` or `authz.denied` (principal, action, key) before it returns.
  - No `corten-driver` lint: the lint the design note sketched would have nothing to catch, since nothing public constructs a proof (design principle 9).
- **Manifest.**
  - `dir NAME PATH protected` is taken only with `take_protected_dir`, and `take_dir` no longer returns it (CWE-288).
  - `authn NAME token ID:HEX,...` and `authn NAME password PATH` are taken with `take_token_authenticator` and `take_password_authenticator`.
- **Tokens.**
  - The key is chosen only among the grant's keys, and the key identifier is checked before use.
  - The audience must equal the grant's name, and `NOTAFTER` must be in the future (the prelude's own clock) and at most 15 minutes away (`MAX_TOKEN_LIFETIME`).
  - At most 512 bytes. The token is never logged.
- **Passwords.**
  - The store is opened with no symbolic link in its path, as a regular file with one link. It is refused at load (`FsError::Exposed`) when any `dir` grant, protected or not, is the store's directory or an ancestor of it, compared by device and inode.
  - "No such user", "wrong password" and "delayed" return the same `AuthnRefused` after the same Argon2id work (a decoy hash).
  - Names follow the token field grammar, and a password over 1,024 bytes is refused before hashing.
  - After 5 failures within 15 minutes, an account answers only after a delay that starts at 1 s and doubles to at most 15 minutes. It is never a permanent lock, and a success clears it.
  - `authn.delayed` and `authn.rehash` are logged.
- **`corten-sandbox`.** A password store becomes a read-only Landlock rule. Before Landlock, the sandbox refuses to start (exit 3) when the store is not a single-link regular file at its canonical path, or when any read-write path, a manifest `dir` or an operator `--rw`, is the store or its ancestor (device and inode).

**Evidence.**
- **macOS:**
  - Clippy `-D warnings` on the workspace: clean.
  - `corten-std` tests: 94 of 94.
  - `corten-sandbox` unit tests: 7 of 7.
  - Rustdoc with warnings denied: clean.
- **Mutations on macOS:** 14 of 14 caught.
  - Token checks (signature, key selection, audience, expiry, lifetime cap), `check` allowing, the unknown-user decoy (by timing ratio), the delay, the failure window and refusal logging.
  - The `protected` flag on another grant kind.
  - The sandbox's ancestor, hard-link and symlink checks.
  - Two first attempts proved nothing: one mutant did not compile, and the window test passed against its mutant, because the delay cap equals the window. Both were rewritten, then caught against a passing baseline. The delay test had also depended on Argon2id speed (a 1 s delay), and now uses a 32 s one.
- **Linux** (`--rm` `rust:1.99.1-slim-bookworm` container, 12 GiB memory cap, 4 build jobs):
  - Clippy `-D warnings` on the workspace: clean, after one fix in a Linux-only test (an `as` conversion macOS Clippy cannot see).
  - `corten-std`: 117 passed, 2 ignored (both existing). This includes the store tests (refused beneath a writable grant, through a symlinked grant, behind a symlink in its own path, as a directory and with a second hard link, against a control beside the grant that loads; malformed lines refused with their line number), `ProtectedDir`'s cross-directory refusal, and `take_dir` refusing a protected grant.
  - `corten-sandbox` unit tests: 8 of 8.
- **Mutations on Linux:** 6 of 6 caught. They disabled the store's ancestor, hard-link, symbolic-link and regular-file checks, `ProtectedDir`'s directory check, and the separation of protected grants from `take_dir`.
- **Not run here:** the corpus, which also builds `corten-std` under its own profile. CI runs it.

**Not covered, and why.**
- **Per-client-address login limits:** the caller sees the address; there is no listener in `corten-std` until batch 6.
- **Token revocation before expiry:** remove the key from the manifest.
- **Re-reading the password store without a restart.**
- **Issuing tools for tokens and stores (design principle 10):** next, with the corpus cases.

## Safe Rust through a crate (2026-11-04)

The applicability audit had asked whether safe Rust can write a weakness with `std` alone. Re-checking the 63 rows marked `unsafe-rust-only` against crates with safe APIs found five that safe Rust can write through a common crate, each probe compiled under `#![forbid(unsafe_code)]` and run (`audit/applicability/crates/README.md`):
- **CWE-560:** `rustix::process::umask` (rustix 1.1.6);
- **CWE-403:** `rustix::io::fcntl_setfd` and `nix::fcntl::fcntl(F_SETFD)` (nix 0.31.3); a child read the descriptor;
- **CWE-910 and 1341:** `nix::unistd::close` on a bare descriptor number; a stale `File` read the file that reused its number, and a double close returned `EBADF`;
- **CWE-134:** `strfmt` 0.2.6 with an external format string (disclosure, no memory corruption).

Still `unsafe` only: CWE-1063 (`ctor` 1.0.13 needs `#[ctor(unsafe)]`, which `forbid(unsafe_code)` refuses), the five signal-handler rows (`signal-hook` 0.4.6's `low_level::register` is `unsafe`), CWE-558 (nix has no `getlogin`), and the memory-safety rows, which rest on the soundness contract.

**Owner decisions (2026-11-04):**
1. A crate-dependent verdict is recorded as reasoning that cites the crate, its version and the measurement, with no program: `scripts/applicability-check.sh` checks programs against stock rustc, which cannot use a crate. The ten programs that showed only the `std` forms were removed (git history keeps them). The probes are kept in `audit/applicability/crates/`, not built by CI.
2. The five rows stay E, by the CWE-918 precedent: the dependency policy refuses these crates unless the operator admits them, so each corpus case gains a `bad-<crate>.rs` variant (`//@ fake-dep`), and `docs/dep-policy.example` bans the APIs for an operator who admits them (design principle 8). Each row's mechanism names both.
3. CWE-134 counts: MITRE's definition is a format string from an external source, which `strfmt` accepts.

**Evidence.**
- **Counts** (`scripts/applicability-table.py`): safe Rust 729 (was 724); safe Rust under Corten 638, unchanged, because all five rows are E and verified; rows resting on programs 362 (was 367). The ledger's buckets do not change.
- **Bans, on Linux** (`cargo corten check` with the example policy, rustix, nix, strfmt and hickory-resolver admitted, plus the four packages they re-export):
  - 9 of 9 fire, each with its own `use of a disallowed method` diagnostic, `hickory_resolver::TlsConfig::insecure_skip_verify` included;
  - the same calls pass with the same admissions and no bans, without the two deprecated `strfmt` entry points (`strfmt_display`, `Format::format_display`), which the profile refuses on its own because deprecated calls are forbidden;
  - a benign program using the same crates passes with the bans.
- **A false start:** the first run admitted only the four direct crates, so the policy refused their re-exports before any lint ran and reported 0 of 9; that measured the harness, not the bans.
- **Corpus:** the six new variants were not run locally. CI's corpus step on the merge of #35 (run 41783860697, Linux) ran them with every other case: 177 of 177 detected, 0 of 177 falsely rejected, 0 broken.

