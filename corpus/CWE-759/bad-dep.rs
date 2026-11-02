//@ kind: checker
//@ fake-dep: sha2
//@ expect: not on the operator's dependency allowlist
// CWE-759 dependency variant: a plain hash of the password with no salt. The prelude governs its own API, not
// what a dependency offers; the operator's policy does not admit the crate.
fn main() {
    sha2::stub();
}
