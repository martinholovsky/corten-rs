//@ expect: -F unsafe-code
// CWE-466: returns a pointer past the end of the buffer.
fn find(xs: &[u8]) -> *const u8 {
    unsafe { xs.as_ptr().add(xs.len()).add(1) }
}
fn main() {
    println!("{:?}", find(&[1, 2, 3]));
}
