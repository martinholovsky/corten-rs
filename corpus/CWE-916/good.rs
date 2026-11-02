//@ deps: corten-std
// Argon2id at a fixed cost; verify refuses stored hashes below the floor.
use corten_std::crypto::{CryptoError, password};
use corten_std::secret::Secret;

pub fn store(pw: &Secret) -> Result<String, CryptoError> {
    password::hash(pw).map(|h| h.as_str().to_owned())
}

fn main() {}
