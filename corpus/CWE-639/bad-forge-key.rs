//@ kind: language
//@ deps: corten-std
//@ expect: E0451
// CWE-639 variant: a key that names another directory than the one it came from.
// `DirKey` has private fields; only `ProtectedDir::key` makes one.
use corten_std::authz::{Authenticated, Authorized, DirKey, Policy, Read, Token, check};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::path::RelPath;

pub fn other(path: RelPath) -> DirKey {
    DirKey { dir: String::from("billing"), path }
}

fn main() {}
