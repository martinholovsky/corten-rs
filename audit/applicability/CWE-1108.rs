//@ compiles: safe
// CWE-1108, excessive reliance on globals: safe statics (Mutex, atomics)
// carry state that every function reads and writes.
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
pub static CURRENT_USER: Mutex<String> = Mutex::new(String::new());
pub static IS_ADMIN: AtomicBool = AtomicBool::new(false);
pub fn login(u: &str) {
    *CURRENT_USER.lock().unwrap() = u.to_string();
    IS_ADMIN.store(u == "root", Ordering::Relaxed);
}
pub fn can_delete() -> bool {
    IS_ADMIN.load(Ordering::Relaxed)
}
