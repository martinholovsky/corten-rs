//@ compiles: unsafe
// CWE-120, classic buffer overflow: copies the input into a fixed 16-byte
// buffer using the input's length, without checking it fits.
pub fn copy_name(input: &[u8]) -> [u8; 16] {
    let mut dst = [0u8; 16];
    unsafe { std::ptr::copy_nonoverlapping(input.as_ptr(), dst.as_mut_ptr(), input.len()) };
    dst
}
