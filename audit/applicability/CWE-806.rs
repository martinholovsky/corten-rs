//@ compiles: unsafe
// CWE-806, buffer access using size of source: the source's length is used
// for a copy into a smaller destination.
pub fn copy_into(dst: &mut [u8; 8], src: &[u8]) {
    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len()) };
}
