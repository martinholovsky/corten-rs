//@ compiles: safe
// CWE-316, cleartext storage of sensitive information in memory. String's
// Drop frees without zeroing, and the reallocation in push_str can leave a
// stale copy of the password in freed heap memory. Safe Rust has no
// zero-on-drop guarantee; that needs a crate such as zeroize.
pub struct Credentials { pub user: String, pub password: String }
pub fn login(user: &str, password: &str) -> Credentials {
    let mut p = String::with_capacity(1);
    p.push_str(password);
    Credentials { user: user.to_owned(), password: p }
}
