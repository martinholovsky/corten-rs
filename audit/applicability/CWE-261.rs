//@ compiles: safe
// CWE-261, weak encoding for password: the stored password is merely
// hex-encoded, which anyone can reverse.
pub fn encode_password(password: &str) -> String {
    password.bytes().map(|b| format!("{b:02x}")).collect()
}
