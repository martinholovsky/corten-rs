//@ kind: language
//@ deps: corten-std
//@ expect: html!: the template leaves
// CWE-83 variant (encoder pre-review, 2026-10-27): an inner template with no
// placeholders opens an event attribute (`<a onclick="`), and the outer
// template's value fills it. Refused since the 2026-10-28 fix (docs/gates/phase-5.md).
pub fn link(v: &str) -> corten_std::html::Html {
    corten_std::html!("{}{}\">x</a>", corten_std::html!("<a onclick=\""), v)
}

fn main() {}
