//@ compiles: unsafe
// CWE-124, buffer underwrite: writes before the start of the buffer using a
// negative offset derived from input.
pub fn set_prev(buf: &mut [u8], back: usize) {
    unsafe { *buf.as_mut_ptr().sub(back) = 0 };
}
