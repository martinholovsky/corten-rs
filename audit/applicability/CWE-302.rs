//@ compiles: safe
// CWE-302, authentication bypass by assumed-immutable data: the role is read
// from a client cookie and trusted, though the client can change it.
pub fn is_admin(cookie_header: &str) -> bool {
    cookie_header.split(';').any(|kv| kv.trim() == "role=admin")
}
