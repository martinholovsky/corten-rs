//@ rejected: E0381
// CWE-824 attempted in safe Rust: a binding must be initialised before use.
pub fn read() -> u8 {
    let p: &u8;
    *p
}
