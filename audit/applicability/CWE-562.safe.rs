//@ rejected: E0515
// CWE-562 attempted in safe Rust: returning a reference to a local is refused
// by the borrow checker.
pub fn local_ref<'a>() -> &'a u64 {
    let x = 42u64;
    &x
}
