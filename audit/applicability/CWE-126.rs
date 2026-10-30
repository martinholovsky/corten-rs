//@ compiles: unsafe
// CWE-126, buffer over-read: builds a slice longer than the buffer from a
// length taken off the wire.
pub fn echo(buf: &[u8], claimed_len: usize) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(buf.as_ptr(), claimed_len) }.to_vec()
}
