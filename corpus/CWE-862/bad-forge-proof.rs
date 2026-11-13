//@ kind: language
//@ deps: corten-std
//@ expect: E0451
// CWE-862 variant: a hand-made proof in place of the check. `Authorized` has
// private fields and no public constructor.
use corten_std::authz::{Authenticated, Authorized, DirKey, Policy, Read, Token, check};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::path::RelPath;

pub fn forge(key: DirKey) -> Authorized<Read, DirKey> {
    Authorized { principal: String::new(), key, action: std::marker::PhantomData }
}

fn main() {}
