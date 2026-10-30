//@ compiles: safe
// CWE-244, heap inspection: growing a Vec that holds a password reallocates;
// the old block is freed without being zeroed (std never zeroes on realloc or
// drop), leaving the secret in freed heap memory.
pub fn credential(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(password.len());
    v.extend_from_slice(password);
    v.extend_from_slice(salt);
    v
}
