//@ rejected: E0133
// CWE-806 attempted in safe Rust: the raw copy is unsafe; slice copies check
// both lengths.
pub fn copy_into(dst: &mut [u8; 8], src: &[u8]) {
    std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
}
