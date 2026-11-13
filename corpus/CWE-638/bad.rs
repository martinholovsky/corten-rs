//@ kind: language
//@ deps: corten-std
//@ expect: E0382
// CWE-638: one check, two accesses. Each protected operation consumes its proof,
// so a second access needs a second check.
use corten_std::authz::{Authenticated, Authorized, DirKey, Policy, Read, Token, check};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::path::RelPath;

pub fn twice(caps: &mut Capabilities, proof: Authorized<Read, DirKey>) -> Option<()> {
    let records = caps.take_protected_dir("records")?;
    let _first = records.read(proof).ok()?;
    let _second = records.read(proof).ok()?;
    Some(())
}

fn main() {}
