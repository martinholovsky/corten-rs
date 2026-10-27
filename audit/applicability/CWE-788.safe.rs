//@ rejected: E0133
// CWE-788 attempted in safe Rust: `buf[buf.len()]` panics; the raw read is
// refused without unsafe.
pub fn last_plus_one(buf: &[u32]) -> u32 {
    *buf.as_ptr().add(buf.len())
}
