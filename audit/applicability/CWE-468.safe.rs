//@ rejected: E0133
// CWE-468 attempted in safe Rust: the mis-scaled raw pointer cannot be
// dereferenced without unsafe; slice indexing scales by element and is checked.
pub fn nth(words: &[u32], n: usize) -> u32 {
    *words.as_ptr().add(n * std::mem::size_of::<u32>())
}
