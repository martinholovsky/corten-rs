//@ compiles: safe
// CWE-688, wrong variable as argument: the signature is checked against the
// user's own key instead of the server key; both have the same type.
fn verify(sig: &[u8], key: &[u8]) -> bool {
    sig.len() == key.len()
}
pub fn check(user_sig: &[u8], _server_key: &[u8], user_key: &[u8]) -> bool {
    verify(user_sig, user_key)
}
