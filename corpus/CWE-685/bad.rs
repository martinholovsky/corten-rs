//@ expect: E0061
// CWE-685: a call with the wrong number of arguments.
fn area(w: u32, h: u32) -> Option<u32> {
    w.checked_mul(h)
}
fn main() {
    println!("{:?}", area(2, 3, 4));
}
