//@ kind: language
//@ deps: corten-std
//@ expect: E0308
// CWE-638 variant: copying a proof to reuse it. Proofs are not `Clone`, so
// `.clone()` only copies the reference, which is not a proof.
use corten_std::authz::{Authenticated, Authorized, DirKey, Policy, Read, Token, check};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::path::RelPath;

pub fn copy(proof: &Authorized<Read, DirKey>) -> Authorized<Read, DirKey> {
    proof.clone()
}

fn main() {}
