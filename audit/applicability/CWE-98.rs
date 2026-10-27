//@ rejected: argument must be a string literal
// CWE-98, PHP file inclusion. Rust has no runtime include: include!/include_str!
// splice a file at compile time and accept only a literal path, so a
// request-controlled name cannot pick source to include.
pub fn page(name: &str) -> &'static str {
    include_str!(name)
}
