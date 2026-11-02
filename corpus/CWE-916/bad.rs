//@ kind: language
//@ deps: corten-std
//@ absent
//@ expect: E0425
// CWE-916: a password hash with a cost the caller lowers. The prelude has no
// cost parameter (weakest evidence: the API is absent).
use corten_std::crypto::{CryptoError, password};
use corten_std::secret::Secret;

pub fn store(pw: &Secret) -> Result<String, CryptoError> {
    password::hash_with_cost(pw, 1, 8).map(|h| h.as_str().to_owned())
}

fn main() {}
