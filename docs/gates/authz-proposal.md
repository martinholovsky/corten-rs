# Strategy 2: authorization and authentication as proof types (design note, 2026-11-10)

Status: **Q1 and Q2 decided (owner, 2026-11-10, the recommendation on both): manifest-flagged `protected` grants; prelude authenticators only.** **Q3 decided (owner, 2026-11-13, the recommendation):** the policy is the program's Rust `Policy`, and Cedar is weighed against the measured prototype, after it. Owner decision 2026-11-10: this is the next Phase 6 strategy (`gates/phase-6.md`, batch 4); 2026-11-13: it goes before the prebuilt driver. Question 14 (spec section 8) already decided the gate: prototype on the corpus, adopt only at 0 false rejections. Nothing here is built.

## What it can and cannot claim

The 16 ledger rows with strategy `authz-types` are all C and all writable in safe Rust. Spec section 7 says Corten cannot decide the authorization matrix, and this note does not change that: whether a rule is *right* stays C. What is mechanical is whether a check *happened* before a protected operation, and whether the check was about the resource actually touched.

| Rows | What the proof types can do | Bucket after a corpus case |
| --- | --- | --- |
| CWE-862 Missing Authorization, 306 Missing Authentication for Critical Function, 288 Authentication Bypass Using an Alternate Path, 638 Not Using Complete Mediation | A protected prelude operation without a proof does not compile, whatever the path to it | E candidates, prelude-only (question 21's bar) |
| CWE-639 Authorization Bypass Through User-Controlled Key, 566 the same through an SQL primary key | The proof names the resource key it was checked for, and the protected lookup takes the key from the proof, not from the caller | E candidates, prelude-only |
| CWE-863, 285, 284 (an incorrect rule), 286, 842 (user management), 280, 287 (how authentication is done), 602, 807, 939 | The rule and the authenticator's correctness stay the program's | Stay C, with the mechanism named in the ledger |

## The bar for an E candidate

The same as `fs-caps-e-proposal.md`: the prelude cannot express the weakness, every way around the prelude is refused (the checker's bans, the dependency policy), it is not decided otherwise, and it costs developers nothing beyond what the protected operation already asks (design principle 1).

## Proposed shape (for the prototype)

```rust
// corten_std::authz (sketch; names are not final)
pub struct Authenticated<P> { /* private */ }           // a principal
pub struct Authorized<A, K> { /* private */ }           // action A on the resource with key K
pub trait Policy<P, A, K> { fn allows(&self, who: &P, action: &A, key: &K) -> bool; }
impl<A, K> Authorized<A, K> { pub fn key(&self) -> &K; }

pub fn check<P, A, K>(who: &Authenticated<P>, action: A, key: K, policy: &impl Policy<P, A, K>)
    -> Result<Authorized<A, K>, Denied>;                  // logged either way (principle 3)
```

- **No public constructor** for `Authenticated` or `Authorized`; private fields make a hand-built proof a compile error (E0451 for a struct literal, E0603 for a tuple-struct constructor; measured on rustc 1.99.1), and a `corten-driver` lint refuses any other route the way `corten_direct_template` does.
- **Proofs are not `Clone` and carry the key.** A protected lookup (`store.get(&proof)`) reads the key from the proof, so a check on resource 1 cannot open resource 2 (CWE-639, 566).
- **Every check is logged** with principal, action, key and outcome before data flows (principle 3), and a denied check is an error, never a weaker default (principle 2).

## Questions for the owner

**Q1. Which operations require a proof?** The prelude does not know which state is protected; only the deployment does.
- **A. A manifest flag on a grant (recommended).** A `dir` or database grant marked `protected` hands the program a capability whose operations take an `Authorized` proof; unmarked grants work as today. Cost: none for programs that mark nothing; the E claim holds for marked grants only, and the manifest states which. It reuses the signed manifest (principle 4) and matches the `served` flag planned for CWE-434.
- B. Program-declared: a `#[corten::protected]` attribute on functions, enforced by a `corten-driver` lint that every caller holds a proof. Cost: an attribute and a lint; the claim then rests on the program marking the right functions, which is the C weakness itself.
- C. Every prelude sink takes a proof. Strongest, and fails principle 1: every file and query call gains ceremony.

**Q2. Who can construct `Authenticated`?**
- **A. Only prelude authenticators the manifest names (recommended):** a password check (`crypto::password`, already Argon2id), a signed token (`crypto::verify_signed` over `VerifyingKeys`), and later a TLS client certificate when a listener exists. A program cannot mint a principal. Cost: programs whose authentication scheme is not in the set cannot use protected grants until it is added (each addition gets the Phase 5 review).
- B. A trait the program implements, named in the manifest. Flexible, but the program can mint principals, so CWE-306 and 288 could not be E.

**Q3. Where does the policy live?** A program's `Policy` implementation (Rust code, reviewed like any other) is the recommendation for the prototype; a policy language (Cedar) adds a dependency (principle 6) and is weighed after the prototype, as the tracker already records.

## Prototype plan (after the answers)

1. `corten_std::authz` with the types above, behind the chosen Q1 and Q2 shape; unit tests, and a mutation per control (a public constructor, a `Clone`, a key not taken from the proof) shown to fail a test.
2. Corpus cases for CWE-862, 306, 288, 638, 639 and 566: a `good.rs` that checks then acts, and every way of skipping it as a `bad-*.rs` (no proof, a forged proof, a proof for another key, a proof reused after a different check, the raw `std` route, a raw database crate through the dependency policy).
3. Detection and false rejection with totals on the full corpus (AGENTS.md rule 2); adopt only at 0 false rejections (question 14). The ledger changes only after that run.

A blocker to name now: there is no listener or request type in `corten-std` (`gates/phase-6.md`, the missing-capabilities row), so the prototype exercises protected *operations*, not request handlers. A handler-level claim waits for batch 6's web types.

## Step 1 built (2026-11-13)

`corten_std::authz`, the manifest's `protected` flag and `authn ... token` grants are built ([`phase-6.md`](phase-6.md), "Batch 4, step 1"). Changes against the sketch above, each an owner decision of 2026-11-13 (spec section 8, questions 23 and 24) or a consequence of one:

- **Q2's authenticators: no passwords.** A password check over hashes the program holds would let the program mint a principal (`crypto::password::hash` accepts anything). A store the program cannot write was built, then removed: the owner decided Corten accepts only phishing-resistant authentication (question 23). Users sign in with passkeys at an identity provider; an exchange gateway, not yet built, turns its assertion into a Corten token, and programs accept only that token, verified with keys from the manifest. TLS client certificates follow as a second authenticator.
- **The token format** is Corten's own, one signed line with no algorithm field, rather than PASETO or JWT, so the prelude adds no dependency. The gateway, outside the prelude, reads the identity provider's format.
- **No `corten-driver` lint.** Private fields and the absence of any public constructor leave no other route for a lint to refuse.

**CWE-566 is not covered by step 1**: `corten-std` has no database capability. A data capability is now scheduled for it (question 24): a database grant whose protected queries take the row key from a proof, with row-level security underneath. CWE-566 stays planned on the chart because that item delivers it.
