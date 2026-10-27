//@ expect: E0515
// CWE-562: returns a reference to a local variable.
fn make() -> &'static u32 {
    let x = 5;
    &x
}
fn main() {
    println!("{}", make());
}
