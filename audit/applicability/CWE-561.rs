//@ compiles: safe
// CWE-561, dead code: the signature check is never called; rustc warns.
fn verify_signature(_body: &[u8]) -> bool {
    true
}
pub fn accept(body: &[u8]) -> bool {
    !body.is_empty()
}
