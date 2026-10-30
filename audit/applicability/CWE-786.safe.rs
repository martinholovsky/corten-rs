//@ rejected: E0133
// CWE-786 attempted in safe Rust: offset and the dereference are unsafe; a
// usize index of pos-1 underflows to a huge value and the bounds check panics.
pub fn previous(buf: &[u8], pos: isize) -> u8 {
    *buf.as_ptr().offset(pos - 1)
}
