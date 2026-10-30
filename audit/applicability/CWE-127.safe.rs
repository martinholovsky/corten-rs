//@ rejected: E0133
// CWE-127 attempted in safe Rust: reading through the offset raw pointer
// requires unsafe; slice indices cannot go below zero.
pub fn peek_before(buf: &[u8], back: usize) -> u8 {
    *buf.as_ptr().sub(back)
}
