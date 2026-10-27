//@ compiles: unsafe
// CWE-823, out-of-range pointer offset: an offset from the input moves the
// pointer outside the allocation before it is read.
pub fn at(buf: &[u8], off: isize) -> u8 {
    unsafe { *buf.as_ptr().offset(off) }
}
