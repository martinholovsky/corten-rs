//@ kind: language
//@ deps: corten-std
//@ expect: private
// CWE-347 variant: wrapping unchecked data as Verified by hand. Its field is
// private; only verify_signed (or map on a Verified) produces one.
use corten_std::crypto::Verified;

pub fn forge(body: Vec<u8>) -> Verified<Vec<u8>> {
    Verified(body)
}

fn main() {}
