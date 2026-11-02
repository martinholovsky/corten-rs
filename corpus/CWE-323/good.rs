//@ deps: corten-std
// The library picks a fresh random nonce for every message.
use corten_std::crypto::{Aad, AeadKey, CryptoError};

pub fn seal_twice(key: &AeadKey, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    Ok((key.seal(msg, Aad(b"ctx"))?, key.seal(msg, Aad(b"ctx"))?))
}

fn main() {}
