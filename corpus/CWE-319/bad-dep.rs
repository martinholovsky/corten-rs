//@ kind: checker
//@ fake-dep: my-http-client
//@ expect: not on the operator's dependency allowlist
// CWE-319 dependency variant: an HTTP client that also speaks plain HTTP. The prelude governs its own API, not
// what a dependency offers; the operator's policy does not admit the crate.
fn main() {
    my_http_client::stub();
}
