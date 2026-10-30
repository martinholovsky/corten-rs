# Encoder pre-review (2026-10-27)

**This is not the independent review** that [`phase-2.md`](phase-2.md) section 5 requires, and it verifies no row. An AI agent with a fresh context worked through the section 5 checklist to find cheap bugs before a human reviewer starts. The same model family wrote the encoders, so its blind spots may overlap theirs. Read this as a list of known problems and of what was looked at, not as assurance.

**Method.**
- The agent wrote probes in a scratch crate that depends on `corten-std` by path, on Rust 1.99.1.
- Every probe asserts that the escape happens. HTML output was parsed with html5ever 0.27, a WHATWG parser, not checked in a browser.
- I re-ran the probes (26 of 26 pass) and read the assertions of every finding below.
- None of the findings has been run under `cargo corten check`. Each one is now a `bad-*.rs` variant in its corpus case, so the corpus answers that question.

## Escapes found

| Encoder | What happens | Corpus variant |
| --- | --- | --- |
| `html!` tokeniser | `<?`, `<!x`, `</ ` and a `<!DOCTYPE` in the body open a bogus comment in WHATWG parsers, ending at the first `>`. `html!` reads them as text, so a placeholder it sees inside a quoted `title` lands in an unquoted `onerror` | `corpus/CWE-79/bad-bogus-comment.rs` |
| `html!` refusals | `<!-{}` is not refused; the value `-` completes `<!--` and comments out the template's structure, which lets a second value land in `onerror` | `corpus/CWE-79/bad-comment-opener.rs` |
| `html!` composition | A template with no placeholders is never checked, and `Html` values are inserted as markup, so `html!("<script>")` or `html!("<a onclick=\"")` leaves a context open that the next value fills | `corpus/CWE-79/bad-composition.rs`, `corpus/CWE-83/bad-composition.rs` |
| `ldap_filter!` | No placeholder position check: `({}=admin)` with `uid>` gives `(uid>=admin)`; `uid:dn:` gives an extensible match. `ldap_dn!` has the same gap for attribute types (not run) | `corpus/CWE-90/bad-attribute-position.rs` |
| `xquery!` | Inside direct element content (`<r>{}</r>`), `"` is ordinary text and `{` starts an enclosed expression (XQuery 3.1, 3.9.1.3), so the value is evaluated. XQuery and XPath 2 comments (`(: {} :)`) can be closed by a value the same way. No XQuery engine was run | `corpus/CWE-652/bad-element-content.rs` |
| `process` `Options` | `Options` has a public `&[&'static str]` field and `ProcessInvocation::new` is public. A runtime string promoted to `'static` through a `static OnceLock<String>` becomes an option (`--checkpoint-action=exec=sh`, with no `--` before it). The profile bans `String::leak` but not `OnceLock` | None: this is argument injection, CWE-88, which is in bucket C |

**Fixed 2026-10-28** ([`phase-5.md`](phase-5.md), part 3). Each probe above now fails to compile with the encoder's refusal, and each corpus variant is refused.

## Template-side gaps (a value cannot reach the text)

- **`sql!` quote tracking** misses `$$ … $$`, MySQL `\'`, backticks, `[ ]`, `--` and `/* */`. A placeholder inside one of them reaches the driver as a literal or comment, so the value is dropped or the parameter count is wrong.
- **`sql!("SELECT {}0", 1)`** renders as `SELECT $10`.

## Clean as checked

- **`escape_into` in HTML:** 2,379 short values in `class`, `title`, `data-*` and text. Each parse gave exactly the expected element and attributes.
- **SQL values:** never enter the query text.
- **`xpath_literal`:** round-trips.
- **`xquery_literal`:** correct as a literal.
- **RFC 4515 filter values and RFC 4514 DN values:** exhaustive up to 4 characters over the special characters.
- **Log records:** every character up to U+3000.
- **CSV quoting:** correct.
- **HTTP headers:** every byte 0x00 to 0xFF tried in a value.
- **Cookies:** match RFC 6265.
- **`process!` operands:** always after `--`.
- **`text!`:** values are not re-parsed.

`crates/corten-std/tests/encoder_properties.rs` adds 10 fixed-seed property tests of 20,000 cases each. Weakening an encoder one way at a time (9 mutations, on a copy) made at least one property fail every time.

## Concerns not confirmed

- **CSV formula prefix:** values with a leading space, U+FEFF or U+200B before `=` are not neutralised. No spreadsheet was available to show whether one evaluates them.
- **HTML `data-*` attributes:** frameworks that execute their values (for example knockout's `data-bind`) are not covered. Whether that matters depends on the framework.
- **Cookie prefix (cosmetic):** `CookieName("__host-x")` gives `__Host-__host-x`; the prefix strip is case-sensitive.

## Not checked

- Fuzzing random HTML templates against html5ever.
- Real XQuery engines, LDAP servers and spreadsheets.
- Non-UTF-8 input and charset sniffing.
- The documented `Html::from_template` direct-call gap ([`phase-2.md`](phase-2.md) section 4).
