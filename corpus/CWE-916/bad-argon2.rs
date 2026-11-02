//@ kind: checker
//@ fake-dep: argon2
//@ expect: not on the operator's dependency allowlist
// CWE-916 dependency variant: the Argon2 crate used directly, with its cost chosen by the caller. The prelude governs its own API, not
// what a dependency offers; the operator's policy does not admit the crate.
fn main() {
    argon2::stub();
}
