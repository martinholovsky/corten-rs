//@ kind: checker
//@ expect: disallowed method
// CWE-918 variant: resolving a caller-chosen name (the first step of a
// request to an internal address).
use std::net::ToSocketAddrs;

pub fn addresses(host: &str) -> usize {
    (host, 443).to_socket_addrs().map_or(0, Iterator::count)
}

fn main() {}
