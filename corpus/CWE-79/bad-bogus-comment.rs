//@ kind: language
//@ deps: corten-std
//@ expect: html!: a placeholder is in a context
// CWE-79 variant (encoder pre-review, 2026-10-27): WHATWG parsers read `<?`
// as a bogus comment that ends at the first `>`. html! reads it as text and
// sees the placeholder inside a quoted `title`, so it lets the value land in
// an unquoted `onerror` value. `<!x` and `</ ` do the same. Refused since the 2026-10-28 fix (docs/gates/phase-5.md).
pub fn page(v: &str) -> corten_std::html::Html {
    corten_std::html!("<? <i title=\"?><img src=x onerror={}>\">", v)
}

fn main() {}
