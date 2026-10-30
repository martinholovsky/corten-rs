//@ compiles: safe
// CWE-591, sensitive data in unlocked memory: the key lives in an ordinary
// heap Vec; std has no mlock, so it can be paged to swap.
pub struct SigningKey(Vec<u8>);
pub fn load(bytes: &[u8]) -> SigningKey {
    SigningKey(bytes.to_vec())
}
