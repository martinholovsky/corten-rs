//@ expect: E0308
// CWE-686: a call with an argument of the wrong type.
fn area(w: u32, h: u32) -> Option<u32> {
    w.checked_mul(h)
}
fn main() {
    println!("{:?}", area("2", 3));
}
