//@ compiles: safe
// CWE-502, deserialisation of untrusted data. A session blob from the client
// is decoded into a struct and trusted as-is, including is_admin. Rust's
// deserialisers do not run gadget code, but the trust error remains.
pub struct Session {
    pub user: String,
    pub is_admin: bool,
}
pub fn decode(blob: &str) -> Session {
    let mut s = Session { user: String::new(), is_admin: false };
    for kv in blob.split(';') {
        match kv.split_once('=') {
            Some(("user", v)) => s.user = v.to_string(),
            Some(("admin", v)) => s.is_admin = v == "1",
            _ => {}
        }
    }
    s
}
