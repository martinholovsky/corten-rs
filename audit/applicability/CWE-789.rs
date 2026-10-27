//@ compiles: safe
// CWE-789, memory allocation with excessive size: the length field from the
// client sizes the allocation without a cap.
pub fn read_body(len_from_header: usize) -> Vec<u8> {
    vec![0u8; len_from_header]
}
