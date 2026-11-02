//@ kind: checker
//@ fake-dep: sha2
//@ expect: not on the operator's dependency allowlist
// CWE-916 dependency variant: a fast hash used for passwords. The prelude governs its own API, not
// what a dependency offers; the operator's policy does not admit the crate.
fn main() {
    sha2::stub();
}
