//@ expect: E0425
// CWE-917: evaluates an expression-language string. Rust and the prelude
// have no expression-language evaluator.
fn main() {
    let expr = String::from("${7*7}");
    let v = el_eval(&expr);
    println!("{v}");
}
