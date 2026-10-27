//@ compiles: safe
// CWE-212, sensitive data not removed before transfer. The export serialises
// every field, including the password hash, for an external partner.
pub struct User {
    pub name: String,
    pub password_hash: String,
}
pub fn export(u: &User) -> String {
    format!("name={};password_hash={}", u.name, u.password_hash)
}
