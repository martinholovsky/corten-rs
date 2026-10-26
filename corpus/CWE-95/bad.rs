//@ expect: E0425
// CWE-95: evaluates text as code. Rust has no eval.
fn main() {
    let code = String::from("1 + 1");
    let v = eval(&code);
    println!("{v}");
}
