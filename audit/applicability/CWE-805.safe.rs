//@ rejected: E0133
// CWE-805 attempted in safe Rust: ptr::copy is unsafe; copy_from_slice
// asserts equal lengths and panics on a wrong length.
pub fn copy_key(src: &[u8], len: usize) -> [u8; 32] {
    let mut dst = [0u8; 32];
    std::ptr::copy(src.as_ptr(), dst.as_mut_ptr(), len);
    dst
}
