//@ rejected: E0133
// CWE-124 attempted in safe Rust: slice indices are usize and checked, and the
// raw pointer form is refused without unsafe.
pub fn set_prev(buf: &mut [u8], back: usize) {
    *buf.as_mut_ptr().sub(back) = 0;
}
