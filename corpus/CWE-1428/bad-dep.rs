//@ kind: checker
//@ fake-dep: my-http-client
//@ expect: not on the operator's dependency allowlist
// CWE-1428 dependency variant: an HTTP client given an http:// URL. The prelude governs its own API, not
// what a dependency offers; the operator's policy does not admit the crate.
fn main() {
    my_http_client::stub();
}
