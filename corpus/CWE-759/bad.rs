//@ kind: language
//@ deps: corten-std
//@ expect: E0061
// CWE-759: a password hash with no salt. hash takes no salt; the library
// generates one.
use corten_std::crypto::{CryptoError, password};
use corten_std::secret::Secret;

pub fn store(pw: &Secret) -> Result<String, CryptoError> {
    password::hash(pw, b"fixed-salt").map(|h| h.as_str().to_owned())
}

fn main() {}
