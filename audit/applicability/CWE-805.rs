//@ compiles: unsafe
// CWE-805, buffer access with incorrect length: copies `len` (from the
// request) into a 32-byte destination.
pub fn copy_key(src: &[u8], len: usize) -> [u8; 32] {
    let mut dst = [0u8; 32];
    unsafe { std::ptr::copy(src.as_ptr(), dst.as_mut_ptr(), len) };
    dst
}
