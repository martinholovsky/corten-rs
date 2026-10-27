//@ rejected: E0382
// CWE-415 attempted in safe Rust: dropping moves the owner, so a second drop
// of the same value is a use of a moved value.
pub fn double_free() {
    let b = Box::new(5u32);
    drop(b);
    drop(b);
}
