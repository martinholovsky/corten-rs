//@ compiles: unsafe
// CWE-466, returned pointer outside the expected range: the function returns a
// pointer past the buffer and the caller dereferences it.
pub fn field(buf: &[u8], off: usize) -> *const u8 {
    buf.as_ptr().wrapping_add(off)
}
pub fn read_field(buf: &[u8], off: usize) -> u8 {
    unsafe { *field(buf, off) }
}
