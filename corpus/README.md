# Compile-fail corpus

One directory per E row in `ledger/cwe-ledger.csv`, named by the row's `proof_test` column (`corpus/CWE-n`). `cargo run -p corten-corpus -- --checker target/debug/cargo-corten` runs every case; CI runs it on every push.

## A case

| File | What it is |
| --- | --- |
| `bad.rs`, `bad-*.rs` | Programs exhibiting the weakness, one per way of writing it. Every one must be rejected for the row to be verified. |
| `good.rs` | The matched benign program. It must build under `cargo corten check`; if it does not, that is a false rejection. |

Each file is a whole `src/main.rs`. Header lines configure it:

| Line | Meaning |
| --- | --- |
| `//@ expect: TEXT` | Required in each bad file. The rejecting build's output must contain TEXT, so a failure for an unrelated reason does not count. Repeatable. |
| `//@ kind: checker` or `//@ kind: language` | Overrides the row's `proof_kind` for this file. `checker`: plain cargo must build it and the checker must reject it. `language`: plain cargo must reject it. |
| `//@ edition: 2021` | Edition of the case crate (default 2024). |
| `//@ deps: corten-std` | The case crate depends on the workspace's `corten-std`. |
| `//@ fake-dep: NAME` | The case crate depends on an empty stub package `NAME` 1.0.0, served from a vendored directory source, so the dependency policy sees the name without a download. Repeatable. |
| `//@ absent` | The bad program uses syntax Rust does not have; reported separately as the weakest evidence. |

## Rules for adding a case

- Write the bad program so plain Rust would build it whenever the mechanism is the checker. The runner checks this (the control).
- Pick `expect` text that names the mechanism: the forbidden lint (`-F unsafe-code`, `-F clippy::as-conversions`) or the compiler error code (`E0381`), not a generic word.
- A new way to write the weakness is a new `bad-*.rs` file, even if it is not detected yet. A row with an undetected variant stays unverified, which is the point.
- After a change, run the corpus with `--mark-verified` and commit the ledger with it. Rows with `review = required` stay unverified even when their case passes; the report lists them.
- A case that needs the prelude depends on it with `//@ deps: corten-std`; the runner builds it as a path dependency, so `corten-std` itself is checked under the profile.
