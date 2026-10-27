//@ compiles: safe
// CWE-400, uncontrolled resource consumption. The client's Content-Length
// sizes the allocation with no cap.
pub fn body_buffer(content_length: usize) -> Vec<u8> {
    vec![0u8; content_length]
}
