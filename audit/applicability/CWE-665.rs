//@ compiles: safe
// CWE-665, improper initialisation. Struct-update syntax fills the unnamed
// field from Default, where 0 means "never lock out", so brute-force lockout
// is silently disabled.
#[derive(Default)]
pub struct LoginPolicy {
    pub lockout_after: u32,
    pub min_password_len: usize,
}
pub fn policy() -> LoginPolicy {
    LoginPolicy { min_password_len: 12, ..Default::default() }
}
