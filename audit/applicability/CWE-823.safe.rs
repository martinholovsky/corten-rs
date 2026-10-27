//@ rejected: E0133
// CWE-823 attempted in safe Rust: wrapping_offset is safe but the resulting
// pointer can only be read in unsafe code.
pub fn at(buf: &[u8], off: isize) -> u8 {
    *buf.as_ptr().wrapping_offset(off)
}
