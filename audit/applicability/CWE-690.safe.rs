//@ rejected: E0133
// CWE-690 attempted in safe Rust: safe APIs return Option/Result rather than
// null, and dereferencing a possibly-null raw pointer requires unsafe.
pub fn first(p: *mut u8) {
    *p = 1;
}
