//@ kind: language
//@ deps: corten-std
//@ expect: html!: a placeholder is in a context
// CWE-79 variant (encoder pre-review, 2026-10-27): `<!-{}` is not refused, so
// the value `-` completes `<!--`. With a second value the comment ends inside
// the template's `title`, and that value lands in an unquoted `onerror`.
// Refused since the 2026-10-28 fix (docs/gates/phase-5.md).
pub fn page(dash: &str, v: &str) -> corten_std::html::Html {
    corten_std::html!("<!-{}<i title=\"--><img src=x onerror={}>\">", dash, v)
}

fn main() {}
