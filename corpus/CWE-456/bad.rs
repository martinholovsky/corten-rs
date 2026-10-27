//@ expect: E0381
// CWE-456: a variable is never initialised before use.
fn main() {
    let x: u32;
    println!("{x}");
}
