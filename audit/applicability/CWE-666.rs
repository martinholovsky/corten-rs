//@ compiles: safe
// CWE-666, operation in the wrong lifecycle phase. encrypt() may be called
// before set_key(); it then runs with an all-zero key instead of failing.
pub struct Cipher {
    key: Option<[u8; 16]>,
}
impl Cipher {
    pub fn new() -> Self {
        Cipher { key: None }
    }
    pub fn set_key(&mut self, k: [u8; 16]) {
        self.key = Some(k);
    }
    pub fn encrypt(&self, data: &mut [u8]) {
        let k = self.key.unwrap_or_default();
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= k[i % 16];
        }
    }
}
