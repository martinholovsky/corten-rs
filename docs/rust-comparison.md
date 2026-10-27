# Corten versus plain Rust: CWE coverage

Of the 944 weaknesses in MITRE CWE 4.20, **853 apply to Rust**: 794 directly and 59 only through `unsafe` code. Corten's drafted classification puts **168 of those 853 in E** (cannot be written), **659 in C** (checkable once the policy is stated) and **26 in O** (out of reach of any language). The other 69 weaknesses are specific to other languages or frameworks, and 22 are not coding weaknesses.

After Phase 0 the ledger holds E 157 / C 670 / O 26 for these 853 (eleven drafted E ids moved to C, with reasons in the ledger); the per-category columns below are the drafted split. 141 of the 175 E rows are now verified by compile-fail tests (`corten-ledger totals`, 2026-10-27); the rest are claims, and 78 of the 186 E ids across the full catalogue were disputed in ratification.

**Status: under audit (2026-10-27, branch `rust-applicability-audit`).** The 853, 794 and 59 above are a classification, not a measurement: they come from MITRE's language tags plus 46 judgement calls, and MITRE's tags record where it documented a weakness, not where a language prevents it. At least one row is wrong: CWE-134 is classed as applying to Rust, but stock rustc rejects its corpus program. Derived from the ledger and corpus today: 853 for Rust including `unsafe`, at most 770 for safe Rust (minus the 59 `unsafe`-only rows and 24 more that stock rustc rejects in the corpus), and 700 for safe Rust with Corten (minus 70 more verified by Corten's checker). The audit tests the applicability rows one category at a time with a program per CWE under stock rustc.

## How each CWE was sorted

Categories come from MITRE's own view [CWE-1400, Comprehensive Categorization](https://cwe.mitre.org/data/definitions/1400.html), which places every one of the 944 weaknesses in exactly one of 22 categories (checked: 944 covered, none twice).

Rust applicability comes from each CWE's `Applicable_Platforms` language list in the MITRE data:

| Applicability | Rule | Ids |
| --- | --- | ---: |
| Applies | Language-agnostic, tagged Rust or "Compiled", or no language listed; plus 43 entries MITRE tags only for other languages whose concept exists in Rust (author's judgement, listed below) | 794 |
| Unsafe Rust only | Tagged only for C, C++, assembly or "Memory-Unsafe"; plus CWE-476, 543 and 587 (author's judgement) | 59 |
| Not applicable | Tagged only for other languages or frameworks (J2EE, Struts, PHP, ASP.NET, Java finalizers, hardware description languages) | 69 |
| Not a coding weakness | Bucket N in the design | 22 |

MITRE's language tags list examples, not every language a weakness occurs in, so the 46 judgement calls matter. They are: integer and cast errors (191, 192, 197, 1335), panics and generic error handling as the analogue of exceptions (248, 396, 397, 460), races (362, 366, 567, 609, 689), mutable-object and visibility issues (374, 375, 493, 495, 496, 500, 607, 766, 767), cloning and serializing secrets (498, 499), equality and hashing consistency (581), control-flow and argument mistakes (462, 478, 481, 685, 688), code and template injection (94, 95, 96, 470, 1336), deserialization (502), database access (566, 619, 1073), regex permissiveness (625), NUL bytes passed to C APIs (626), XML DTDs (827), skipped cleanup (1091); and as unsafe-only, null pointers (476), unsynchronized singletons (543) and fixed addresses (587).

## By category

"Plain Rust today" is the author's summary of what the stable language and standard library do for the category on their own; it has not been verified per CWE. Section numbers point to [`spec.md`](spec.md).

| Category (CWE-1400) | Apply to Rust | Only via `unsafe` | Plain Rust today | Corten mechanism | Corten E / C / O |
| --- | ---: | ---: | --- | --- | --- |
| Access Control | 148 | 0 | Nothing in the language; authority is ambient (any code can open files, sockets, processes). | Capabilities passed in from a signed manifest; evidence types such as `Permission<Delete, Account>` (4.3, 4.11) | 1 / 146 / 1 |
| Poor Coding Practices | 111 | 5 | Clippy flags many of these, but only if enabled. | Lints enforced by the gate rather than opt-in (section 10) | 19 / 79 / 13 |
| Resource Lifecycle Management | 100 | 7 | RAII and ownership manage most lifetimes; `mem::forget` and leaks are safe. | Linear handles, no `mem::forget`, compiler-supplied finalizers, quotas (4.1, 4.12) | 17 / 83 / 0 |
| Improper Neutralization | 68 | 3 | Strings flow into SQL, HTML, shell and log sinks via `format!` with no checks. | Typed sinks only (`sql!`, `html!`, `process!`, `log_record!`); no raw constructors (4.5, 4.6) | 7 / 61 / 0 |
| File Handling | 46 | 0 | `std::fs` opens any string path; no traversal or symlink protection. | `DirCap` + `PathSeg` on `openat2` with `RESOLVE_BENEATH` and no symlinks (4.4) | 44 / 2 / 0 |
| Exposed Resource | 39 | 0 | `pub` fields, `static` items and ambient file and network access are all available. | No ambient authority, no mutable public statics, capability-scoped resources (4.3) | 10 / 29 / 0 |
| Memory Safety | 37 | 31 | Safe Rust prevents use-after-free, double free and out-of-bounds access, but any crate may use `unsafe` or FFI. | No application `unsafe` or in-process FFI, enforced by the gate; foreign code isolated in Wasm or a process (4.1, 4.14) | 16 / 21 / 0 |
| Injection | 36 | 0 | `Command` can run a shell; query and template strings are plain `String`s. | No shell strings, no `eval`, no DTDs; context-typed sinks (4.5) | 28 / 7 / 1 |
| Insufficient Control Flow Management | 35 | 2 | Exhaustive `match` prevents missing cases; panics and early returns can skip logic. | No exceptions or `finally`; must-use results; typestates for required order (4.7, 4.11) | 10 / 25 / 0 |
| Concurrency | 33 | 4 | `Send`/`Sync` already rule out data races in safe Rust; logical races, TOCTOU and deadlocks remain. | Structured concurrency, bounded channels, affine lock guards, `blocking` effect (4.8) | 8 / 25 / 0 |
| Sensitive Information Exposure | 33 | 0 | `#[derive(Debug)]` prints secrets; no data labels. | `Secret<T>` without `Debug`/`Display`, labelled errors, non-elidable wipe (4.9, 4.7) | 0 / 33 / 0 |
| Encryption | 22 | 0 | No cryptography in `std`; safety depends on the crate chosen. | Goal-oriented crypto API: TLS 1.3, AEAD with managed nonces, no skip-verification (4.10) | 0 / 22 / 0 |
| Protection Mechanism Failure | 20 | 0 | Nothing in the language. | Fail-closed defaults, `Secure`/`HttpOnly` cookies, refused operations on weak platforms (4.4, 4.6) | 0 / 17 / 3 |
| Randomness | 19 | 0 | No RNG in `std`; quality depends on the crate. | OS CSPRNG only, behind a `random` capability (4.10) | 0 / 19 / 0 |
| Violation of Secure Design Principles | 17 | 0 | Nothing in the language. | Least authority by construction; the rest is design review (4.3, section 7) | 0 / 14 / 3 |
| Comparison | 15 | 1 | `PartialEq` can be derived for anything; no constant-time comparison in `std`. | Domain types instead of raw strings; constant-time comparison for secrets (4.5, 4.9) | 2 / 10 / 3 |
| Insufficient Verification of Data Authenticity | 15 | 0 | No signing or verification in `std`. | Signed updates and manifests, typed trust stores (4.10, 4.15) | 0 / 15 / 0 |
| Resource Control | 14 | 0 | No quotas or budgets. | Mandatory budgets on parse, decode and allocate; per-component limits (4.12) | 2 / 12 / 0 |
| Improper Input Validation | 12 | 1 | No built-in notion of untrusted input. | `Untrusted<T>` parsed into domain types; refinements in decidable fragments (4.5, 4.13) | 0 / 12 / 0 |
| Incorrect Calculation | 12 | 5 | Integer overflow panics in debug builds but wraps in release by default; `as` truncates silently. | Checked arithmetic in every profile, no implicit casts, distinct wrapping types (4.2) | 3 / 7 / 2 |
| Component Interaction | 11 | 0 | No checks on what crates or processes exchange. | Schema-checked broker IPC and declared effects per package (4.14, 4.15) | 0 / 11 / 0 |
| Improper Check or Handling of Exceptional Conditions | 10 | 0 | `Result` is `#[must_use]`, but `let _ =` discards it; `unwrap` and panics are common. | Linear must-use `Result`, exhaustive matching, supervision of panicked components (4.7) | 1 / 9 / 0 |
| **Total** | **853** | **59** | | | **168 / 659 / 26** |

## Where Corten differs most from plain Rust

- **Injection, neutralization and file handling.** Plain Rust does nothing here; strings and paths flow freely. These are where Corten claims the most E (28 of 36 injection ids, 44 of 46 file-handling ids), because the closed prelude removes the raw sinks.
- **Memory safety.** Plain safe Rust already prevents most of it. The gap is `unsafe` and FFI in any dependency, which plain Rust allows and cannot stop a crate author from re-enabling (spec section 10). Corten removes in-process `unsafe` and moves foreign code out of process.
- **Calculation.** Plain Rust wraps silently in release builds and truncates silently with `as`. Corten checks every operation in every profile.
- **Access control, cryptography, secrets, design.** Mostly C: Corten gives the mechanism (capabilities, evidence types, `Secret<T>`, goal-oriented crypto), but someone still has to state the policy.

## The 59 weaknesses only reachable through `unsafe`

Plain safe Rust already excludes these; they come back through `unsafe` blocks or FFI in your code or any dependency. Corten forbids application `unsafe` and in-process FFI and enforces that at the gate. Drafted buckets: E 30, C 29 (C where a mandatory runtime check such as bounds checking is what stops them).

CWE-119 (C), CWE-120 (C), CWE-121 (C), CWE-122 (C), CWE-123 (C), CWE-124 (C), CWE-125 (C), CWE-126 (C), CWE-127 (C), CWE-128 (C), CWE-131 (C), CWE-135 (C), CWE-170 (E), CWE-194 (C), CWE-195 (C), CWE-196 (C), CWE-242 (E), CWE-243 (E), CWE-244 (C), CWE-364 (C), CWE-415 (E), CWE-416 (E), CWE-463 (E), CWE-464 (E), CWE-466 (E), CWE-467 (E), CWE-468 (E), CWE-469 (E), CWE-476 (E), CWE-479 (E), CWE-482 (E), CWE-483 (E), CWE-543 (E), CWE-558 (C), CWE-560 (E), CWE-562 (E), CWE-587 (E), CWE-588 (E), CWE-590 (E), CWE-676 (C), CWE-680 (C), CWE-690 (E), CWE-761 (E), CWE-762 (E), CWE-763 (E), CWE-781 (C), CWE-782 (C), CWE-785 (C), CWE-786 (C), CWE-787 (C), CWE-788 (C), CWE-805 (C), CWE-806 (C), CWE-822 (E), CWE-823 (E), CWE-824 (E), CWE-825 (E), CWE-839 (C), CWE-843 (E)

## The 69 weaknesses that do not apply to Rust

CWE-5, CWE-6, CWE-7, CWE-8, CWE-9, CWE-11, CWE-12, CWE-13, CWE-98, CWE-102, CWE-103, CWE-104, CWE-105, CWE-106, CWE-107, CWE-108, CWE-109, CWE-110, CWE-111, CWE-245, CWE-246, CWE-382, CWE-383, CWE-395, CWE-473, CWE-486, CWE-487, CWE-491, CWE-492, CWE-536, CWE-537, CWE-554, CWE-555, CWE-556, CWE-564, CWE-568, CWE-572, CWE-574, CWE-575, CWE-576, CWE-577, CWE-578, CWE-579, CWE-580, CWE-582, CWE-583, CWE-585, CWE-586, CWE-594, CWE-600, CWE-608, CWE-616, CWE-621, CWE-624, CWE-627, CWE-917, CWE-1086, CWE-1087, CWE-1090, CWE-1174, CWE-1221, CWE-1223, CWE-1224, CWE-1235, CWE-1251, CWE-1272, CWE-1298, CWE-1311, CWE-1321

## Per-CWE detail

Every row of [`ledger/cwe-ledger.csv`](../ledger/cwe-ledger.csv) now carries `cwe1400_category` and `rust_applicability` beside the drafted bucket. Filter it for any category above.
