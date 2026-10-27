//@ rejected: E0133
// CWE-123 attempted in safe Rust: an integer may be cast to a pointer, but
// writing through it requires unsafe.
pub fn write_what_where(addr: usize, value: usize) {
    *(addr as *mut usize) = value;
}
