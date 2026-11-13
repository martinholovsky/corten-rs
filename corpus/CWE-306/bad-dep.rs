//@ kind: checker
//@ fake-dep: jsonwebtoken
//@ expect: not on the operator's dependency allowlist
// CWE-306 dependency variant: a token library that lets the program verify (or skip
// verifying) tokens itself. The prelude governs its own API, not what a dependency offers;
// the operator's policy does not admit the crate.
fn main() {
    jsonwebtoken::stub();
}
