//@ compiles: safe
// CWE-909, missing initialisation of a critical resource. The rule table is
// never loaded at startup; it stays empty, and an empty table allows all.
use std::sync::Mutex;
static DENY_RULES: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub fn allowed(host: &str) -> bool {
    !DENY_RULES.lock().unwrap().iter().any(|r| r == host)
}
