//@ kind: language
//@ deps: corten-std
//@ expect: is private
// CWE-306: a principal the program makes up instead of authenticating.
// `Authenticated` has private fields; only a manifest authenticator returns one.
use corten_std::authz::{Authenticated, Authorized, DirKey, Policy, Read, Token, check};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::path::RelPath;

pub fn trust(name: &str) -> Authenticated {
    Authenticated { principal: name.to_owned(), authenticator: String::from("api") }
}

fn main() {}
