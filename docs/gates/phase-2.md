# Phase 2 gate: capabilities and typed sinks

Date: 2026-10-26. Toolchain: Rust 1.99.1. Platforms: macOS (development) and Linux (podman `rust:1.99.1-slim-bookworm`, and CI on `ubuntu-24.04`). Gate, from spec section 9: "the injection and path compile-fail corpus passes; the encoders get an independent review before any E claim on them."

**Result: half passed.** The corpus passes: 76 of 76 Phase 2 cases detected, 0 false rejections. The independent encoder review has not happened; it cannot be done by the author of the encoders. So the 26 rows that rest on an encoder stay unverified (`review = required` in the ledger), and Phase 2's gate is open until a reviewer signs them off. The 50 path and process rows, which rest on the absence of an ambient API plus the `openat2` monitor, are verified.

## 1. What Phase 2 built (`crates/corten-std`)

| Spec item | What exists | Where |
| --- | --- | --- |
| `DirCap` and `PathSeg` on `openat2`; refuse elsewhere | `PathSeg` per [`docs/pathseg.md`](../pathseg.md); `DirCap` opens with `RESOLVE_BENEATH`, `NO_SYMLINKS`, `NO_MAGICLINKS`, `NO_XDEV`, `O_NOFOLLOW`, `O_CLOEXEC`; exclusive 0600 temp files; every other target returns `Unsupported` | `path.rs`, `fs.rs` |
| `sql!`, `html!`, `process!`, `log_record!`, header, URL, CSV and template types with no raw constructors | `sql!`, `html!`, `process!`, `log_record!`, `text!`, `ldap_filter!`, `ldap_dn!`, `xpath!`, `xquery!`, `HeaderName`/`HeaderValue`/`SetCookie`, `CsvCell`. A URL type is not built | one module each |
| Signed capability manifest handed to `main` | `Capabilities::load`: Ed25519 (`ed25519-compact`) checked before parsing, 64 KiB cap, directories opened at load | `manifest.rs` |
| `Secret<T>` with the observable wipe, `mlock` and no-dump | `Secret`: `zeroize` on drop, `region::lock`, the process marked non-dumpable on Linux, constant-time compare, no `Debug`/`Display`/`Clone` | `secret.rs` |

**The template design.** Every sink macro defines a private type whose associated constant holds the literal template, and the public constructor is generic over that type. An associated constant is evaluated at compile time, so no runtime value can become sink text, including one laundered into a `&'static str` through a `OnceLock` (the corpus case `bad-launder.rs` fails with E0015). Placeholder counts, the HTML context rules and the "no placeholder inside quotes" rule are compile-time assertions.

**Driver interfaces.** `SqlExecutor`, `HtmlWriter`, `HeaderWriter`, `LogWriter`, `CsvWriter`, `TextSender`, `LdapSearcher`, `XPathEvaluator` and `XQueryEvaluator` accept only the typed values, so a driver written against them cannot receive a string. No driver is implemented.

`corten-std` passes the Corten profile itself: every corpus case that depends on it builds it as a path dependency under `cargo corten check`, so its own code is held to the profile on every run.

## 2. Corpus result

| Measure | Phase 2 (76 cases) | All cases (169) |
| --- | ---: | ---: |
| Detection: every bad program rejected for the expected reason | 76 of 76 | 160 of 169 |
| False rejection | **0 of 76** | 0 of 169 |
| Controls failed | 0 | 0 |
| Broken cases | 0 | 0 |
| Passed but unverified pending encoder review | 26 at the Phase 2 run | 25 (CWE-838 now fails on `bad-direct.rs`, below) |
| Ledger rows verified | 50 new | 135 of 175 |

The figures before the CWE-838 variant was added are from the Phase 2-only run; the "all cases" column is the run recorded in [`corpus-report.md`](corpus-report.md).

Per row, the variants are:

- **Path rows** (CWE-22 to 40, 42 to 57, 59, 61, 64, 66, 67, 69, 72, 363, 626, 1386): the input-built path opened with ambient `std::fs` builds under plain Rust and is rejected by the checker (`checker` kind, with the control); passing a `String` to `DirCap::open_file` does not compile; forging a `PathSeg` does not compile.
- **Process rows** (CWE-77, 78, 426 to 428): `std::process::Command` with a shell string, a `PATH` search or an input-chosen `PATH` is rejected by the checker; forging a `ProcessInvocation` does not compile.
- **Sink rows**: a formatted `String` passed to the driver interface, a forged value, a runtime-laundered template and a non-literal macro template each fail to compile; HTML contexts that escaping cannot make safe (`href`, `src`, `on*`, `style`, `<script>`, `<{}>`) and SQL or XPath placeholders inside quotes fail at compile time.

The runtime half of the path claims is the monitor, tested on Linux (`crates/corten-std/src/fs.rs`): a symbolic link as the last component or in the middle of the path is refused (`ELOOP`), each with a control showing ordinary resolution follows it; exclusive creation refuses a planted name or link; temp files are 0600 and unique; `remove_file` does not follow a final link. Removing `RESOLVE_NO_SYMLINKS` makes the mid-path test fail (mutation-checked).

## 3. Defects the corpus and tests found during Phase 2

| Defect | Found by | Fixed |
| --- | --- | --- |
| `html!("<{}>", v)` was accepted: with `v = "script"` it renders `<script>`, and escaping does not touch letters. Same for `<!{}` and a `--` value | The HTML refusal unit test | Placeholders straight after `<`, `<!`, `<?`, `</` are refused |
| The HTML context, SQL-quote and placeholder-count assertions were inline consts in a generic function: evaluated only when the program is built, so `cargo check`, and therefore `cargo corten check`, accepted `html!("<a href=\"{}\">", url)` | The corpus (`bad-context.rs`, `bad-quoted.rs` built under plain check) | Every macro now also asserts in a plain `const` item, which `cargo check` evaluates. Removing it fails six cases (mutation-checked) |
| `openat2` returned `EINVAL` for every read: it refuses a non-zero mode without `O_CREAT`, unlike `open` | The Linux tests | Mode is 0 unless creating |

## 4. Bypass hunt and known gaps

| Attempt | Result |
| --- | --- |
| A `String` where a typed value is required | Does not compile (E0308) |
| Forging a typed value by struct literal | Does not compile (private constructor or field) |
| A runtime template through `OnceLock` in a `Template` impl | Does not compile (E0015) |
| A non-literal template in a macro | Does not compile (no macro rule matches) |
| **`Html::from_template` called directly with a hand-written `Template`** | **Passes `cargo check`, fails `cargo build`** with the encoder's context error (measured on 1.99.1). The weakness cannot ship, but `cargo corten check` does not report it. Recorded as `corpus/CWE-838/bad-direct.rs`, which keeps CWE-838 "not detected". Closing it needs the checker to build rather than check, or a lint against direct `from_template` calls outside the macros |
| `Html` interpolated into an attribute | Escaped, not kept as markup (unit test) |

Not built, so the rows depending on them stay unverified: CWE-619 (no database cursor API), and the URL type from the spec's sink list.

## 5. What a reviewer must check

The encoders are the trusted base of 26 E claims. A reviewer independent of the author should check, at minimum:

- `html.rs`: the tokeniser's handling of every state against the WHATWG tokenizer for the subset allowed, the attribute allowlist, and `escape_into`;
- `sql.rs`, `xpath.rs`: the quote tracking in `placeholders_outside_quotes`;
- `ldap.rs`: RFC 4515 and RFC 4514 escaping;
- `xpath.rs`: `xpath_literal` and `xquery_literal`;
- `log.rs`, `csv.rs`, `http.rs`, `process.rs`, `text.rs`: their escaping, neutralisation and grammar checks.

A review is recorded by replacing `required` in each row's `review` column with a link to the review; `corten-ledger check` then allows `verified`.
