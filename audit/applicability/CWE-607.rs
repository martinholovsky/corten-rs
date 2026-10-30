//@ compiles: safe
// CWE-607, public static field referencing a mutable object. The static is
// immutable as a binding, but the Mutex inside lets any code in any crate
// rewrite the allow-list.
use std::sync::Mutex;
pub static ALLOWED_HOSTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
