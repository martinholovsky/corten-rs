//@ kind: language
//@ deps: corten-std
//@ expect: is private
// CWE-639 variant: changing a checked proof's key after the check.
use corten_std::authz::{Authenticated, Authorized, DirKey, Policy, Read, Token, check};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::path::RelPath;

pub fn retarget(mut proof: Authorized<Read, DirKey>, key: DirKey) -> Authorized<Read, DirKey> {
    proof.key = key;
    proof
}

fn main() {}
