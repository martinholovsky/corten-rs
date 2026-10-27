//@ rejected: E0133
// CWE-787 attempted in safe Rust: the unchecked write is unsafe; `buf[i] = v`
// is bounds-checked and panics.
pub fn set(buf: &mut [u8], i: usize, v: u8) {
    *buf.get_unchecked_mut(i) = v;
}
