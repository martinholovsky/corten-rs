//@ deps: corten-std
// Only a successful signature check produces Verified.
use corten_std::crypto::{CryptoError, SignatureBytes, Verified, VerifyingKey, verify_signed};

pub fn apply(update: &Verified<Vec<u8>>) -> usize {
    update.get().len()
}

pub fn receive(
    body: Vec<u8>,
    sig: SignatureBytes<'_>,
    key: VerifyingKey<'_>,
) -> Result<usize, CryptoError> {
    let checked = verify_signed(body, sig, key)?;
    Ok(apply(&checked))
}

fn main() {}
