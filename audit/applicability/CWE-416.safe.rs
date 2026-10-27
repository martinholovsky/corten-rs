//@ rejected: E0505
// CWE-416 attempted in safe Rust: the borrow checker refuses to drop the Vec
// while a reference into it is still used.
pub fn use_after_free() -> u8 {
    let v = vec![1u8, 2, 3];
    let r = &v[0];
    drop(v);
    *r
}
