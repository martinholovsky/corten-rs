//@ kind: language
//@ deps: corten-std
//@ expect: is private
// CWE-918 variant: forging a network capability for a caller-chosen host.
// NetCap has no public constructor; only a signed manifest grants one.
use corten_std::net::{Host, NetCap};

pub fn forge(host: String) -> NetCap {
    NetCap::new("x".to_owned(), Host::Name(host), 443, true)
}

fn main() {}
