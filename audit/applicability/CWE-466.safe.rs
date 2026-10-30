//@ rejected: E0133
// CWE-466 attempted in safe Rust. Creating the out-of-range raw pointer is safe
// (wrapping_add), but no safe code can dereference it, so it cannot be used;
// a function returning `&buf[off]` panics instead.
pub fn field(buf: &[u8], off: usize) -> *const u8 {
    buf.as_ptr().wrapping_add(off)
}
pub fn read_field(buf: &[u8], off: usize) -> u8 {
    *field(buf, off)
}
