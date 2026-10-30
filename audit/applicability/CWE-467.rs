//@ compiles: safe
// CWE-467, sizeof on a pointer type: size_of_val(&key) measures the reference
// (8 bytes), not the 32-byte key, so only a prefix is used as the MAC key.
pub fn mac_key(key: &[u8; 32]) -> Vec<u8> {
    key[..std::mem::size_of_val(&key)].to_vec()
}
