//@ compiles: safe
// CWE-498, cloneable type containing sensitive data. Deriving Clone on a key
// type lets any holder duplicate the secret, defeating single-owner wiping.
#[derive(Clone)]
pub struct SessionKey {
    key: [u8; 32],
}
impl SessionKey {
    pub fn new(key: [u8; 32]) -> Self { SessionKey { key } }
    pub fn len(&self) -> usize { self.key.len() }
}
