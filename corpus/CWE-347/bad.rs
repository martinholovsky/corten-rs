//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// CWE-347: data used as if its signature had been checked.
use corten_std::crypto::Verified;

pub fn apply(update: &Verified<Vec<u8>>) -> usize {
    update.get().len()
}

pub fn receive(body: Vec<u8>) -> usize {
    apply(&body)
}

fn main() {}
