//@ expect: -F unsafe-code
// CWE-493: a security-relevant public variable anyone can change.
pub static mut LIMIT: u32 = 10;
fn main() {
    unsafe { LIMIT = 1_000_000 };
    let v = unsafe { LIMIT };
    println!("{v}");
}
