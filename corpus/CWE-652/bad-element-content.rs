//@ kind: language
//@ deps: corten-std
//@ expect: xquery!: a placeholder
// CWE-652 variant (encoder pre-review, 2026-10-27): inside direct element
// content, `"` is ordinary text and `{` starts an enclosed expression
// (XQuery 3.1, 3.9.1.3), so the quoted literal does not contain the value:
// `{doc('/etc/passwd')}` is evaluated. Not run on an XQuery engine.
// Refused since the 2026-10-28 fix (docs/gates/phase-5.md).
pub fn query(v: &str) -> corten_std::xpath::XQueryExpr {
    corten_std::xquery!("<r>{}</r>", v)
}

fn main() {}
