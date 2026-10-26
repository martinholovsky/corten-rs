//@ expect: E0106
// CWE-496: stores caller-owned data in a private field by reference.
pub struct Store {
    data: &mut [u32],
}
fn main() {
    let mut buf = [1u32, 2];
    let s = Store { data: &mut buf };
    println!("{:?}", s.data);
}
