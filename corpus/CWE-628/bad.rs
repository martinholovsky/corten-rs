//@ expect: E0061
// CWE-628: a call whose arguments do not match the function.
fn area(w: u32, h: u32) -> Option<u32> {
    w.checked_mul(h)
}
fn main() {
    println!("{:?}", area(2));
}
