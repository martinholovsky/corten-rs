//@ compiles: safe
// CWE-836, password hash used instead of the password: the client sends a
// hash and it is compared to the stored hash, so the stored hash itself is
// the credential.
pub fn login(stored_hash_hex: &str, client_hash_hex: &str) -> bool {
    stored_hash_hex == client_hash_hex
}
