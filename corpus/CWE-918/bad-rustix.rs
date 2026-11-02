//@ kind: checker
//@ fake-dep: rustix
//@ expect: not on the operator's dependency allowlist
// CWE-918 dependency variant: raw sockets through a system-call crate. The prelude governs its own API, not
// what a dependency offers; the operator's policy does not admit the crate.
fn main() {
    rustix::stub();
}
