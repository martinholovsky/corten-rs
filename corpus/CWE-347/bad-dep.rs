//@ kind: checker
//@ fake-dep: ed25519-dalek
//@ expect: not on the operator's dependency allowlist
// CWE-347 dependency variant: a signature crate whose verify result the caller may ignore. The prelude governs its own API, not
// what a dependency offers; the operator's policy does not admit the crate.
fn main() {
    ed25519_dalek::stub();
}
