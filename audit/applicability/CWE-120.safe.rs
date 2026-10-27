//@ rejected: E0133
// CWE-120 attempted in safe Rust. The unchecked copy is an unsafe function;
// the safe form `dst[..input.len()].copy_from_slice(input)` panics on a long
// input instead of overflowing.
pub fn copy_name(input: &[u8]) -> [u8; 16] {
    let mut dst = [0u8; 16];
    std::ptr::copy_nonoverlapping(input.as_ptr(), dst.as_mut_ptr(), input.len());
    dst
}
