//@ rejected: E0133
// CWE-822 attempted in safe Rust: dereferencing an integer-derived raw pointer
// requires unsafe.
pub fn handle(msg_ptr_from_client: usize) -> u8 {
    *(msg_ptr_from_client as *const u8)
}
