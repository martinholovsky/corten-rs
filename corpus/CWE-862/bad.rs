//@ kind: language
//@ deps: corten-std
//@ expect: E0308
// CWE-862: a protected read with no authorization check. `read` takes a proof, not
// a key, so skipping `check` does not type-check.
use corten_std::authz::{Authenticated, Authorized, DirKey, Policy, Read, Token, check};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::path::RelPath;

pub fn read_unchecked(caps: &mut Capabilities, path: RelPath) -> Option<Vec<u8>> {
    let records = caps.take_protected_dir("records")?;
    let key = records.key(path);
    records.read(key).ok()?.read_to_end(1_048_576).ok()
}

fn main() {}
