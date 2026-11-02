//@ deps: corten-std
// The library generates a 16-byte random salt for every hash.
use corten_std::crypto::{CryptoError, password};
use corten_std::secret::Secret;

pub fn store(pw: &Secret) -> Result<String, CryptoError> {
    password::hash(pw).map(|h| h.as_str().to_owned())
}

fn main() {}
