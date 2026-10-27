//@ compiles: safe
// CWE-321, hard-coded cryptographic key: every installation encrypts with the
// same key literal (the cipher itself stands in for any real algorithm).
const KEY: [u8; 16] = *b"0123456789abcdef";
pub fn encrypt(plain: &[u8]) -> Vec<u8> {
    plain.iter().enumerate().map(|(i, b)| b ^ KEY[i % KEY.len()]).collect()
}
