//@ compiles: unsafe
// CWE-127, buffer under-read: reads before the start of the buffer.
pub fn peek_before(buf: &[u8], back: usize) -> u8 {
    unsafe { *buf.as_ptr().sub(back) }
}
