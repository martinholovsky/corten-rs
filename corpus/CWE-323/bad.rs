//@ kind: language
//@ deps: corten-std
//@ expect: E0061
// CWE-323: a nonce chosen by the caller, reused for two messages. seal takes
// no nonce, so there is nothing to reuse.
use corten_std::crypto::{Aad, AeadKey, CryptoError};

pub fn seal_twice(key: &AeadKey, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let nonce = [0u8; 24];
    Ok((key.seal(msg, &nonce, Aad(b"ctx"))?, key.seal(msg, &nonce, Aad(b"ctx"))?))
}

fn main() {}
