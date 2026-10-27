//@ expect: argument must be a string literal
// CWE-98: includes a file chosen at run time. include! takes only a literal.
fn main() {
    let name = String::from("page.rs");
    include!(name);
}
