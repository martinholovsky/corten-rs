//@ rejected: E0133
// CWE-122 attempted in safe Rust: set_len and the raw copy are unsafe; the safe
// `v.extend_from_slice(data)` reallocates instead of overflowing.
pub fn append(v: &mut Vec<u8>, data: &[u8]) {
    let end = v.len();
    std::ptr::copy_nonoverlapping(data.as_ptr(), v.as_mut_ptr().add(end), data.len());
    v.set_len(end + data.len());
}
