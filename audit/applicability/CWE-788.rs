//@ compiles: unsafe
// CWE-788, access after end of buffer: reads the element one past the end.
pub fn last_plus_one(buf: &[u32]) -> u32 {
    unsafe { *buf.as_ptr().add(buf.len()) }
}
