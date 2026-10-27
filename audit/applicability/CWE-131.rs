//@ compiles: safe
// CWE-131, incorrect calculation of buffer size: hex encoding needs 2 bytes per
// input byte but the buffer is sized at one; the write past it panics instead
// of overflowing, yet the size calculation is wrong.
pub fn hex(input: &[u8]) -> Vec<u8> {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut out = vec![0u8; input.len()];
    for (i, b) in input.iter().enumerate() {
        out[2 * i] = D[(b >> 4) as usize];
        out[2 * i + 1] = D[(b & 15) as usize];
    }
    out
}
