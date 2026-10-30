//@ kind: language
//@ deps: corten-std
//@ expect: html!: the template leaves
// CWE-79 variant (encoder pre-review, 2026-10-27): a template without
// placeholders is never checked, and `Html` values are inserted as markup.
// An inner `html!("<script>")` leaves a script element open, so the next
// value is script text. Refused since the 2026-10-28 fix (docs/gates/phase-5.md).
pub fn page(v: &str) -> corten_std::html::Html {
    corten_std::html!("{}{}", corten_std::html!("<script>"), v)
}

fn main() {}
