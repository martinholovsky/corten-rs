//@ compiles: unsafe
// CWE-787, out-of-bounds write via get_unchecked_mut with an unvalidated index.
pub fn set(buf: &mut [u8], i: usize, v: u8) {
    unsafe { *buf.get_unchecked_mut(i) = v };
}
