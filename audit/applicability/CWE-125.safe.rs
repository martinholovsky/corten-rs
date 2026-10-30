//@ rejected: E0133
// CWE-125 attempted in safe Rust: the unchecked read is unsafe; `buf[i]` is
// bounds-checked and panics (that panic is CWE-129/248, not a read outside).
pub fn read_at(buf: &[u8], i: usize) -> u8 {
    *buf.get_unchecked(i)
}
