//@ rejected: E0133
// CWE-126 attempted in safe Rust: from_raw_parts is unsafe; `&buf[..claimed_len]`
// panics when the claimed length exceeds the buffer (Heartbleed cannot leak).
pub fn echo(buf: &[u8], claimed_len: usize) -> Vec<u8> {
    std::slice::from_raw_parts(buf.as_ptr(), claimed_len).to_vec()
}
