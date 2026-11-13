//@ kind: language
//@ deps: corten-std
//@ expect: E0061
// CWE-639: a check on one key, then an access with a key the caller chose. The
// protected read takes its path from the proof and nowhere else.
use corten_std::authz::{Authenticated, Authorized, DirKey, Policy, Read, Token, check};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::path::RelPath;

pub fn swap(
    caps: &mut Capabilities,
    proof: Authorized<Read, DirKey>,
    chosen: RelPath,
) -> Option<Vec<u8>> {
    let records = caps.take_protected_dir("records")?;
    records.read(proof, chosen).ok()?.read_to_end(1_048_576).ok()
}

fn main() {}
