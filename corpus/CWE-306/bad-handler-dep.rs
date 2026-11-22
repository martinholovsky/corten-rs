//@ kind: checker
//@ fake-dep: axum
//@ expect: not on the operator's dependency allowlist
// CWE-306 handler dependency variant: a web framework whose routes run with no
// authentication unless the program adds it. The prelude governs its own
// listener, not what a dependency offers; the operator's policy does not admit
// the crate.
fn main() {
    axum::stub();
}
