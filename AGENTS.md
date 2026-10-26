# AGENTS.md — working in the Corten repository

Instructions for AI coding agents (Claude Code, Codex, Cursor, Copilot and others) and for humans who want the same ground rules. `CLAUDE.md` points here; this file is the single source.

## What this repository is

Corten is a hardened Rust profile that aims to make whole classes of security bugs impossible to write and the rest mechanically checkable. Today it is a **design only**: [`docs/spec.md`](docs/spec.md) is the design, [`docs/rust-comparison.md`](docs/rust-comparison.md) compares it with plain Rust, and [`ledger/cwe-ledger.csv`](ledger/cwe-ledger.csv) holds one row per MITRE CWE weakness. Read the README first, then the spec section your task touches.

## Rules that are specific to Corten

1. **An E claim needs a failing build, not an argument.** A CWE may be marked E (eliminated by construction) only when a compile-fail test shows a program exhibiting the weakness does not build, and a matched benign program does build. Record the test in the ledger's `proof_test` column. Until then the row stays `unverified`.
2. **Report the false-rejection rate beside every detection number.** A rule that catches bad code but also rejects good code is not done. Every result states both: how many bad programs failed to build, and how many good programs failed too, with the totals.
3. **The checker supplies its own configuration.** `cargo corten check` must inject its flags (for example `-F unsafe_code`) and lint lists itself. Never read them from the repository being checked: an author can delete an in-source `#![forbid]` and the crate builds again (measured, spec section 10).
4. **Do not move a CWE between buckets without a reason in the ledger.** Bucket changes go through the ledger with the mechanism and, for disputed ids, a response to the reasons in `dispute_reasons`. The 14 ids disputed by two or more panel members (spec section 6) are decided first.
5. **Respect the open decisions.** The nine questions in spec section 8 are owner decisions. Do not implement one side of a question that is still Open; ask.
6. **Names.** The project is Corten. Crates and tools are `cargo-corten`, `corten-std` and `corten-*`. The bare `corten` crate name on crates.io belongs to someone else.
7. **Keep the CWE notice intact.** Any copy of CWE names or identifiers keeps MITRE's copyright line and terms (`ledger/NOTICE`).
8. **The design panel's transcript is not public.** Do not ask for it or try to reconstruct it; the spec and the ledger (including `dispute_reasons`) are the public record.

## General working rules

- **Validate before you assert.** Check claims about code, versions, tools and external facts against a primary source (read the file, run the command, fetch the official docs) before stating them, and label anything unverified.
- **Keep docs current in the same change.** When behaviour, rules or the ledger change, update the spec, README and this file in the same commit.
- **Prove a check can fail before trusting it passed.** A scan or test that reports "nothing found" counts only if the same instrument finds a planted positive (for example, gitleaks finding a planted token).
- **Gates.** Commits run gitleaks via pre-commit (`.pre-commit-config.yaml`); install hooks with `pre-commit install --hook-type pre-commit --hook-type pre-push`. Rust checks (fmt, clippy, tests, audit) are not in the config yet; the maintainer adds them when the Cargo workspace lands, by re-running the SOTA `init-gates.sh` generator.

## Optional: SOTA engineering skills

The maintainer builds and audits with the [SOTA-skills](https://github.com/martinholovsky/SOTA-skills) library. If you have it installed, route through its `sota` skill before building or auditing code, and load `sota-rust`, `sota-code-security` and `sota-testing` for most work here.
