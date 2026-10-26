# Ferrum

**Ferrum is a hardened Rust profile that makes whole classes of security bugs impossible to write, and makes the rest mechanically checkable.**

> Status: **design only.** There is no implementation yet. Every "impossible to write" claim in this repository is a target to be proven by tests, not a property you get today.

## What Ferrum is

Ferrum is a security profile of Rust: same syntax, compiler and tooling, but with a locked-down standard library and stricter rules.

Its goal is to remove security bugs by construction instead of finding them later. Code can't touch files, the network or processes without being explicitly handed that permission. No string can become a SQL query, HTML or a shell command without going through a typed builder. Arithmetic is always checked, errors can't be silently ignored, and memory-unsafe or foreign code runs isolated, never in-process.

It's measured against all 944 weaknesses in MITRE's CWE catalogue. The target is to make roughly a fifth of them impossible to write and most of the rest mechanically checkable, while being honest about the small share no language can fix: business logic, intent and design.

### What it is not

- **Not a new language.** It's Rust with a stricter profile.
- **Not "bulletproof".** It can enforce a wrong policy perfectly. Authorization rules, business logic and requirements are still your job.
- **Not finished.** Today it's a ratified design with no implementation.

## Where the design came from

The design was produced in October 2026 by a panel of five frontier models from five vendors (OpenAI, Google, xAI, DeepSeek, Qwen). Each wrote a blind proposal, they debated for three rounds while seeing each other only as anonymous letters, and all five ratified a joint specification with reservations. Two of the five started out proposing a new language; all five converged on a Rust profile. The panel ran inside the author's AethelGard project.

The drafted classification of the 944 CWE weaknesses:

| Bucket | Meaning | Ids |
| --- | --- | ---: |
| E | Eliminated by construction: cannot be written | 186 (108 undisputed) |
| C | Mechanically checkable once the policy is stated | 710 |
| O | Out of reach of any language | 26 |
| N | Not a coding weakness | 22 |

Treat E = 186 as a ceiling: in ratification the panel challenged 78 of those ids down to C.

## How it will be enforced

A rule only holds if the check that enforces it runs somewhere the code's author cannot change. Ferrum is planned in five layers: crates that make the safe way easy (`ferrum-std`, typed sinks); `cargo ferrum check`, which builds with flags and lints it supplies itself; the same rules applied to every dependency; a CI gate that signs proof the build passed; and a deployment check plus runtime sandbox that refuse anything without that proof. The first deliverable is `cargo ferrum check` plus a GitHub Action that runs it and signs the result. Details, including a test showing why in-repo rules alone are not enough: [`docs/spec.md`](docs/spec.md) section 10.

## Repository layout

| Path | What it is |
| --- | --- |
| [`docs/spec.md`](docs/spec.md) | The full design: mechanisms, ratification amendments, open decisions, roadmap, enforcement model, risks |
| [`ledger/cwe-ledger.csv`](ledger/cwe-ledger.csv) | One row per CWE with its drafted bucket and disputes; columns for mechanism, TCB assumption and proof test, to be filled in |
| [`ledger/NOTICE`](ledger/NOTICE) | MITRE CWE copyright and licence |

## Where to help

The roadmap in [`docs/spec.md`](docs/spec.md) section 9 starts with Phase 0: turning the ledger into a per-CWE record of mechanism and proof test, and settling the nine open design decisions in section 8. Issues and pull requests on either are welcome.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

CWE names and identifiers are © The MITRE Corporation and used under the [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html); see [`ledger/NOTICE`](ledger/NOTICE). CWE is a trademark of The MITRE Corporation. Ferrum is not affiliated with or endorsed by MITRE.
