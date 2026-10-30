//@ rejected: is private
// CWE-499, serializable class not denying serialization. Rust has no implicit
// serialization: another module cannot read private fields to dump them, and
// Debug/serde impls exist only if the author opts in.
mod creds {
    pub struct Creds {
        password: [u8; 16],
    }
    impl Creds {
        pub fn new() -> Self { Creds { password: [b'x'; 16] } }
    }
}
pub fn serialize(c: &creds::Creds) -> Vec<u8> {
    c.password.to_vec()
}
