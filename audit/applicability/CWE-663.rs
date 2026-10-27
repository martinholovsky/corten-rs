//@ compiles: safe
// CWE-663, non-reentrant function in a concurrent context: the function keeps
// its intermediate result in a static and reads it back under a second lock;
// another thread can overwrite it in between.
use std::sync::Mutex;
static SCRATCH: Mutex<String> = Mutex::new(String::new());
pub fn render(user: &str) -> String {
    if let Ok(mut s) = SCRATCH.lock() { *s = format!("<b>{user}</b>"); }
    SCRATCH.lock().map(|s| s.clone()).unwrap_or_default()
}
