# Corten versus plain Rust: CWE coverage

Of the 944 weaknesses in MITRE CWE 4.20, **785 can be written in Rust** with `unsafe` allowed, **722 in safe Rust**, and **641 in safe Rust under Corten** once its verified eliminations are taken out (81 of them; 608 would remain if every claimed elimination held). Of the rest, 67 need a construct Rust does not have and 92 are not weaknesses of code (chip and hardware design, physical attacks, process, documentation).

These numbers come from a per-CWE review on 2026-10-27, recorded with its reasoning in [`rust-applicability.md`](rust-applicability.md) and [`audit/applicability/table.csv`](../audit/applicability/table.csv). Wherever the compiler prevents a weakness, or could plausibly have prevented it, a program in `audit/applicability/` shows the outcome, and `scripts/applicability-check.sh` re-checks every program against stock rustc: 367 of the 944 rows rest on programs. The remaining rows are logic, design or policy weaknesses that no compiler prevents, or constructs Rust lacks, each with its reasoning. A compiling program shows a weakness can be written; that it exhibits the weakness is the judgement stated in its comment.

Corten's buckets over the 785 that can be written: E 152 / C 602 / O 26 / N 5, with 119 of the E rows verified by compile-fail tests (`corten-ledger totals`, 2026-10-27). Read the unverified E rows as targets. The 5 in N (CWE-1113, CWE-1114, CWE-1115, CWE-1116, CWE-1117) are comment, whitespace and documentation weaknesses the design classed as not coding; the review found them to be source code, as their parent CWE-1078 already is in the ledger. Their bucket is unchanged pending a ledger decision.

## How each CWE was sorted

The first classification (Phase 0) took Rust applicability from each CWE's `Applicable_Platforms` language list in MITRE's data, plus 46 judgement calls. MITRE's tags record where a weakness has been documented, not where a language prevents it, and that rule counted 853 for Rust. The per-CWE review replaced it. Each CWE got three answers, with reasoning:

| Question | Answers |
| --- | --- |
| Can a Rust program contain it, `unsafe` allowed (std only; external systems stubbed)? | yes / no / n/a |
| Can safe Rust contain it? | yes / no / n/a |
| What does Corten do? | from the ledger: eliminated (verified or claimed), checkable (C), out of reach (O) |

What changed from the tag-based count: 68 weaknesses of chip design, hardware, physical attacks or process were counted as applying to Rust because MITRE tags them "Not Language-Specific" (now n/a); 11 counted as applying use constructs Rust does not have (C-style fall-through, class inheritance, virtual destructors, runtime-named variables); and 17 counted as `unsafe`-only can be written in safe Rust (`as` casts that sign-extend or wrap, `chroot`, stale bytes in reused buffers). In the other direction, reading uninitialised memory (E0381), unsynchronised mutable statics and signal handlers need `unsafe`. Measured, not recalled: std opens files, sockets and pipes close-on-exec (a child process saw no new descriptor, macOS and Linux).

## By category

Counts are over the weaknesses that can be written in Rust. "Plain Rust today" is a summary of what the stable language and standard library do for the category on their own; the per-CWE answers are in [`rust-applicability.md`](rust-applicability.md). Section numbers point to [`spec.md`](spec.md).

| Category (CWE-1400) | `unsafe` allowed | Safe Rust | Only via `unsafe` | Plain Rust today | Corten mechanism | Corten E / C / O / N | E verified |
| --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| Poor Coding Practices | 113 | 101 | 12 | Clippy flags many of these, but only if enabled. | Lints enforced by the gate rather than opt-in (section 10) | 16 / 79 / 13 / 5 | 15 |
| Access Control | 111 | 111 | 0 | Nothing in the language; authority is ambient (any code can open files, sockets, processes). | Capabilities passed in from a signed manifest; evidence types such as `Permission<Delete, Account>` (4.3, 4.11) | 1 / 109 / 1 / 0 | 0 |
| Resource Lifecycle Management | 89 | 83 | 6 | RAII and ownership manage most lifetimes; `mem::forget` and leaks are safe. | Linear handles, no `mem::forget`, compiler-supplied finalizers, quotas (4.1, 4.12) | 17 / 72 / 0 / 0 | 14 |
| Improper Neutralization | 68 | 67 | 1 | Strings flow into SQL, HTML, shell and log sinks via `format!` with no checks. | Typed sinks only (`sql!`, `html!`, `process!`, `log_record!`); no raw constructors (4.5, 4.6) | 7 / 61 / 0 / 0 | 4 |
| File Handling | 46 | 46 | 0 | `std::fs` opens any string path; no traversal or symlink protection. | `DirCap` + `PathSeg` on `openat2` with `RESOLVE_BENEATH` and no symlinks (4.4) | 42 / 4 / 0 / 0 | 42 |
| Exposed Resource | 38 | 36 | 2 | `pub` fields, `static` items and ambient file and network access are all available. | No ambient authority, no mutable public statics, capability-scoped resources (4.3) | 8 / 30 / 0 / 0 | 7 |
| Memory Safety | 37 | 7 | 30 | Safe Rust prevents use-after-free, double free and out-of-bounds access, but any crate may use `unsafe` or FFI. | No application `unsafe` or in-process FFI, enforced by the gate; foreign code isolated in Wasm or a process (4.1, 4.14) | 16 / 21 / 0 / 0 | 16 |
| Injection | 36 | 36 | 0 | `Command` can run a shell; query and template strings are plain `String`s. | No shell strings, no `eval`, no DTDs; context-typed sinks (4.5) | 25 / 10 / 1 / 0 | 3 |
| Sensitive Information Exposure | 31 | 31 | 0 | `#[derive(Debug)]` prints secrets; no data labels. | `Secret<T>` without `Debug`/`Display`, labelled errors, non-elidable wipe (4.9, 4.7) | 0 / 31 / 0 / 0 | 0 |
| Concurrency | 30 | 22 | 8 | `Send`/`Sync` already rule out data races in safe Rust; logical races, TOCTOU and deadlocks remain. | Structured concurrency, bounded channels, affine lock guards, `blocking` effect (4.8) | 8 / 22 / 0 / 0 | 8 |
| Insufficient Control Flow Management | 28 | 28 | 0 | Exhaustive `match` prevents missing cases; panics and early returns can skip logic. | No exceptions or `finally`; must-use results; typestates for required order (4.7, 4.11) | 5 / 23 / 0 / 0 | 4 |
| Encryption | 22 | 22 | 0 | No cryptography in `std`; safety depends on the crate chosen. | Goal-oriented crypto API: TLS 1.3, AEAD with managed nonces, no skip-verification (4.10) | 0 / 22 / 0 / 0 | 0 |
| Randomness | 19 | 19 | 0 | No RNG in `std`; quality depends on the crate. | OS CSPRNG only, behind a `random` capability (4.10) | 0 / 19 / 0 / 0 | 0 |
| Protection Mechanism Failure | 17 | 17 | 0 | Nothing in the language. | Fail-closed defaults, `Secure`/`HttpOnly` cookies, refused operations on weak platforms (4.4, 4.6) | 0 / 14 / 3 / 0 | 0 |
| Comparison | 16 | 16 | 0 | `PartialEq` can be derived for anything; no constant-time comparison in `std`. | Domain types instead of raw strings; constant-time comparison for secrets (4.5, 4.9) | 2 / 11 / 3 / 0 | 2 |
| Insufficient Verification of Data Authenticity | 15 | 15 | 0 | No signing or verification in `std`. | Signed updates and manifests, typed trust stores (4.10, 4.15) | 0 / 15 / 0 / 0 | 0 |
| Violation of Secure Design Principles | 13 | 13 | 0 | Nothing in the language. | Least authority by construction; the rest is design review (4.3, section 7) | 0 / 10 / 3 / 0 | 0 |
| Improper Input Validation | 12 | 11 | 1 | No built-in notion of untrusted input. | `Untrusted<T>` parsed into domain types; refinements in decidable fragments (4.5, 4.13) | 0 / 12 / 0 / 0 | 0 |
| Incorrect Calculation | 12 | 11 | 1 | Integer overflow panics in debug builds but wraps in release by default; `as` truncates silently. | Checked arithmetic in every profile, no implicit casts, distinct wrapping types (4.2) | 3 / 7 / 2 / 0 | 3 |
| Resource Control | 12 | 10 | 2 | No quotas or budgets. | Mandatory budgets on parse, decode and allocate; per-component limits (4.12) | 1 / 11 / 0 / 0 | 1 |
| Component Interaction | 11 | 11 | 0 | No checks on what crates or processes exchange. | Schema-checked broker IPC and declared effects per package (4.14, 4.15) | 0 / 11 / 0 / 0 | 0 |
| Improper Check or Handling of Exceptional Conditions | 9 | 9 | 0 | `Result` is `#[must_use]`, but `let _ =` discards it; `unwrap` and panics are common. | Linear must-use `Result`, exhaustive matching, supervision of panicked components (4.7) | 1 / 8 / 0 / 0 | 0 |
| **Total** | **785** | **722** | **63** | | | **152 / 602 / 26 / 5** | **119** |

## Where Corten differs most from plain Rust

- **Injection, neutralization and file handling.** Plain Rust does nothing here; strings and paths flow freely. These are where Corten claims the most E (28 of 36 injection ids, 44 of 46 file-handling ids), because the closed prelude removes the raw sinks.
- **Memory safety.** Plain safe Rust already prevents most of it. The gap is `unsafe` and FFI in any dependency, which plain Rust allows and cannot stop a crate author from re-enabling (spec section 10). Corten removes in-process `unsafe` and moves foreign code out of process.
- **Calculation.** Plain Rust wraps silently in release builds and truncates silently with `as`. Corten checks every operation in every profile.
- **Access control, cryptography, secrets, design.** Mostly C: Corten gives the mechanism (capabilities, evidence types, `Secret<T>`, goal-oriented crypto), but someone still has to state the policy.

## The 63 weaknesses only reachable through `unsafe`

Safe Rust excludes these; they come back through `unsafe` blocks or FFI in your code or any dependency. Corten forbids application `unsafe` and in-process FFI and enforces that at the gate. Each has a program that compiles only with `unsafe` and one showing rustc rejects the safe form. Current buckets: E 38, C 25, O 0.

CWE-111 (E), CWE-119 (C), CWE-120 (C), CWE-121 (C), CWE-122 (C), CWE-123 (C), CWE-124 (C), CWE-125 (C), CWE-126 (C), CWE-127 (C), CWE-134 (E), CWE-170 (E), CWE-242 (E), CWE-364 (C), CWE-403 (E), CWE-415 (E), CWE-416 (E), CWE-432 (C), CWE-456 (E), CWE-457 (E), CWE-466 (E), CWE-468 (E), CWE-470 (C), CWE-475 (E), CWE-476 (E), CWE-479 (E), CWE-499 (C), CWE-558 (C), CWE-560 (E), CWE-562 (E), CWE-567 (E), CWE-586 (E), CWE-587 (E), CWE-588 (E), CWE-590 (E), CWE-680 (C), CWE-685 (E), CWE-690 (E), CWE-761 (E), CWE-762 (E), CWE-763 (E), CWE-781 (C), CWE-785 (C), CWE-786 (C), CWE-787 (C), CWE-788 (C), CWE-805 (C), CWE-806 (C), CWE-822 (E), CWE-823 (E), CWE-824 (E), CWE-825 (E), CWE-828 (C), CWE-831 (C), CWE-843 (E), CWE-908 (E), CWE-910 (E), CWE-1056 (E), CWE-1058 (E), CWE-1063 (C), CWE-1082 (E), CWE-1098 (E), CWE-1341 (E)

## The 67 weaknesses that need a construct Rust does not have

CWE-5, CWE-6, CWE-7, CWE-8, CWE-9, CWE-11, CWE-12, CWE-13, CWE-98, CWE-102, CWE-103, CWE-104, CWE-105, CWE-106, CWE-107, CWE-108, CWE-109, CWE-110, CWE-245, CWE-246, CWE-382, CWE-383, CWE-395, CWE-473, CWE-481, CWE-483, CWE-484, CWE-487, CWE-491, CWE-492, CWE-520, CWE-536, CWE-537, CWE-554, CWE-555, CWE-556, CWE-564, CWE-568, CWE-572, CWE-574, CWE-575, CWE-576, CWE-577, CWE-578, CWE-579, CWE-580, CWE-582, CWE-583, CWE-584, CWE-594, CWE-600, CWE-608, CWE-616, CWE-621, CWE-624, CWE-627, CWE-914, CWE-1042, CWE-1045, CWE-1055, CWE-1070, CWE-1079, CWE-1087, CWE-1097, CWE-1174, CWE-1235, CWE-1321

## The 92 weaknesses that are not about code

CWE-1053, CWE-1059, CWE-1104, CWE-1110, CWE-1111, CWE-1112, CWE-1118, CWE-1189, CWE-1190, CWE-1191, CWE-1192, CWE-1193, CWE-1209, CWE-1221, CWE-1222, CWE-1223, CWE-1224, CWE-1231, CWE-1232, CWE-1233, CWE-1234, CWE-1239, CWE-1242, CWE-1243, CWE-1244, CWE-1245, CWE-1247, CWE-1248, CWE-1251, CWE-1252, CWE-1253, CWE-1256, CWE-1257, CWE-1258, CWE-1259, CWE-1260, CWE-1261, CWE-1262, CWE-1263, CWE-1264, CWE-1267, CWE-1268, CWE-1270, CWE-1271, CWE-1272, CWE-1273, CWE-1274, CWE-1276, CWE-1278, CWE-1280, CWE-1281, CWE-1282, CWE-1283, CWE-1290, CWE-1292, CWE-1294, CWE-1296, CWE-1297, CWE-1298, CWE-1299, CWE-1300, CWE-1301, CWE-1302, CWE-1303, CWE-1304, CWE-1310, CWE-1311, CWE-1312, CWE-1313, CWE-1314, CWE-1315, CWE-1316, CWE-1317, CWE-1318, CWE-1319, CWE-1320, CWE-1323, CWE-1326, CWE-1328, CWE-1330, CWE-1331, CWE-1332, CWE-1334, CWE-1338, CWE-1342, CWE-1351, CWE-1384, CWE-1420, CWE-1421, CWE-1422, CWE-1423, CWE-1431

## Per-CWE detail

[`rust-applicability.md`](rust-applicability.md) has every CWE with its answers, Corten status and reasoning; `rust_applicability` in [`ledger/cwe-ledger.csv`](../ledger/cwe-ledger.csv) carries the same verdict (`applies`, `unsafe-rust-only`, `not-applicable`, `not-coding`).
