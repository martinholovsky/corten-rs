//@ kind: language
//@ deps: corten-std
//@ expect: E0277
//@ expect: Clone
// CWE-638 variant: copying a proof through the trait. Proofs are not `Clone`.
use corten_std::authz::{Authenticated, Authorized, DirKey, Policy, Read, Token, check};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::path::RelPath;

pub fn copy(proof: &Authorized<Read, DirKey>) -> Authorized<Read, DirKey> {
    <Authorized<Read, DirKey> as Clone>::clone(proof)
}

fn main() {}
