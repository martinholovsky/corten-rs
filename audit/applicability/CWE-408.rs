//@ compiles: safe
// CWE-408, early amplification: the expensive decompression runs before the
// token is checked, so unauthenticated clients can burn CPU and memory.
pub fn handle(token: &str, compressed: &[u8]) -> Option<Vec<u8>> {
    let body = inflate(compressed);
    if token != "expected" {
        return None;
    }
    Some(body)
}
fn inflate(c: &[u8]) -> Vec<u8> {
    c.iter().flat_map(|&b| std::iter::repeat_n(b, 1 << 16)).collect()
}
