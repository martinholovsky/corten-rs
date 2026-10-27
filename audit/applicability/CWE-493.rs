//@ compiles: safe
// CWE-493, critical public variable without final. The security policy is a
// public global with public fields; any code in any crate can lower it.
use std::sync::Mutex;
pub struct Policy {
    pub max_login_attempts: u32,
    pub require_mfa: bool,
}
pub static POLICY: Mutex<Policy> = Mutex::new(Policy { max_login_attempts: 3, require_mfa: true });
pub fn attacker_code() {
    POLICY.lock().unwrap().require_mfa = false;
}
