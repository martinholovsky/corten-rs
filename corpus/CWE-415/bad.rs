//@ expect: -F unsafe-code
// CWE-415: frees the same allocation twice.
fn main() {
    let p = Box::into_raw(Box::new(5u32));
    unsafe {
        drop(Box::from_raw(p));
        drop(Box::from_raw(p));
    }
}
