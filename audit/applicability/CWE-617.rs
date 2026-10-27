//@ compiles: safe
// CWE-617, reachable assertion: a request field drives an assert!, so a client
// can panic the server.
pub fn parse_frame(declared_len: usize, body: &[u8]) -> &[u8] {
    assert!(declared_len <= body.len(), "bad frame");
    &body[..declared_len]
}
