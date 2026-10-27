# Phase 4: refinements, labels and lock order (post-MVP)

Date: 2026-10-27. Toolchain: Rust 1.99.1 (and the Phase 3b driver for the full checker). Platforms: macOS and Linux (podman `rust:1.99.1-slim-bookworm`).

The roadmap (spec section 9) lists three items and no gate; none of them backs an E row. Every flow these mechanisms address stays C (spec sections 4.8, 4.9 and 4.13), so the measure here is whether each mechanism rejects what it claims at `cargo check` time, with a control, and whether removing it is caught.

**Result: all three built in `corten-std` as libraries, each rejection tested with its exact compiler message and mutation-checked; no ledger row moves.**

## 1. What was built

| Roadmap item | Module | Mechanism |
| --- | --- | --- |
| Decidable refinements with the three-outcome rule | `refine` | `Bounded<MIN, MAX>`: `bounded!(MIN, MAX, VALUE)` proves a literal by evaluating `Bounded::new` in a plain `const` item, which `cargo check` evaluates, so an out-of-range literal does not compile. `Bounded::new`, `checked_add` and `checked_sub` are the runtime check, returning `Result`. `copy_into(src, dst)` is spec 4.13's `copy` example with the length obligation as a runtime check. There is no unchecked constructor, and no `unsafe`, so nothing becomes an optimizer assumption |
| Flow-sensitive labels at write, log, respond and serialize | `label`, `manifest` | `Labeled<T, L>` over `Public < Internal < Confidential < Secret`. Only `Public` values come out (`into_inner`); `Labeled` has no `Display`, so the sink macros refuse it. `relabel` only raises; `map` keeps and `join` raises the level, and both take `fn` pointers so nothing captured can leak. `declassify` to `Public` needs a `DeclassifyCap`, granted only by the signed manifest's new `declassify NAME` line, and writes a `log_record!` naming the capability, the source level and a literal reason before release |
| Lock-order contracts | `sync` | `lock_order!(A, B, C)` declares levels; `OrderedMutex<L, T>::lock` takes the token for the held level and requires `L: LockAfter<Held>`, so taking locks against the order, or two at one level, does not type-check. Tokens are not `Send`. One `LockRoot` per thread at a time is the runtime check |

## 2. Tests

| Test | Result |
| --- | --- |
| `crates/corten-std/tests/phase4.rs`: 14 fixtures, each checked with `cargo check` as its own crate. 11 must fail with their exact message: an out-of-range `bounded!` (`evaluation panicked: bounded!: the value is outside the range`), the private constructor, `into_inner` above `Public`, a `Secret` into `html!` and into `log_record!`, `relabel` downward, a capturing closure in `map`, a forged `DeclassifyCap`, locks against the order, two locks at one level, a token sent to a thread. 3 good programs must pass | 1 of 1 test (14 fixtures) passes |
| Unit tests: refine 3, label 2 (including that the declassification record names the capability and level but not the value), sync 3 (order with skipped levels, one root per thread, poisoning), manifest `declassify` grammar and take-once | 45 of 45 `corten-std` unit tests pass; 10 doctests, including one `compile_fail` per module |
| The 3 good programs through `cargo corten check` (both passes, sandboxed, Linux) | 3 of 3 pass |

Mutation checks, on a copy of the repository: each change below makes a test fail (7 of 7 caught).

| Mutation | Caught by |
| --- | --- |
| `relabel` without the `FlowsTo` bound | `label_lowered` builds |
| `into_inner` for every level | `label_into_inner` builds |
| `map` taking a capturing closure | `label_capturing_map` builds |
| `lock_order!` also allowing the reverse order | `lock_inverted` builds |
| `LockToken` made `Send` | `lock_token_to_thread` builds |
| `bounded!` not proving the range | `refine_out_of_range` builds |
| A second `LockRoot` on one thread allowed | `one_root_per_thread_at_a_time` |

Two of the rejections arrive as a type mismatch rather than a missing trait: with one `LockAfter` impl that fits, the solver infers the held level as `Unlocked` and reports `expected &mut LockToken<'_, Unlocked>, found &mut LockToken<'_, Ledger>`; likewise for `relabel`. The fixtures expect that text, and the good fixtures show the allowed direction compiles, so the failure is the ordering and not a fixture bug.

## 3. What they do not do

- **Refinements**: integer ranges and lengths only. Bounds do not propagate through arithmetic in types (that needs `generic_const_exprs`, which stable Rust lacks), so sums are runtime checks. No finite-state protocol or temporal typestate is provided beyond what Rust's own types give.
- **Labels**: a `fn` can still reach ambient output the profile allows (standard output, a panic message), so labels check stated flows; they do not prove non-interference. Levels are a fixed chain without the spec's principal sets. Labels are per value, not tracked across control flow. Sinks have one clearance, `Public`.
- **Lock order**: only these mutexes. A plain `std::sync::Mutex`, a database lock, a channel or a join is outside the order, and so is locking across processes.

Each of these is why the corresponding weaknesses (information exposure, deadlock, off-by-one) stay C in the ledger.
