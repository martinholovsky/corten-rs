//@ compiles: safe
// CWE-532, sensitive information in a log file. The login path logs the
// cleartext password.
pub fn login(user: &str, password: &str) -> bool {
    eprintln!("login attempt user={user} password={password}");
    !password.is_empty()
}
