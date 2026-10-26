//@ expect: expected `{`
// CWE-483: a branch body without braces, so only the first statement is guarded.
fn main() {
    let ready = true;
    if ready println!("a");
    println!("b");
}
