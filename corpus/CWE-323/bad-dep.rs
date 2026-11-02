//@ kind: checker
//@ fake-dep: chacha20poly1305
//@ expect: not on the operator's dependency allowlist
// CWE-323 dependency variant: a raw AEAD crate whose encrypt takes the caller's nonce. The prelude governs its own API, not
// what a dependency offers; the operator's policy does not admit the crate.
fn main() {
    chacha20poly1305::stub();
}
