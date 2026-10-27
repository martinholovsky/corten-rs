//@ compiles: safe
// CWE-79, cross-site scripting. The name is written into HTML unescaped, so
// "<script>...</script>" runs in the visitor's browser. A String is just text
// to the type system; nothing marks it as needing HTML escaping.
pub fn greeting_page(name: &str) -> String {
    format!("<html><body><p>Hello, {name}</p></body></html>")
}
