//@ compiles: safe
// CWE-488, data element exposed to the wrong session. A process-wide static
// holds "the current user"; concurrent request handlers on different threads
// overwrite and read each other's value.
use std::sync::Mutex;
static CURRENT_USER: Mutex<String> = Mutex::new(String::new());
pub fn handle(request_user: &str) -> String {
    *CURRENT_USER.lock().unwrap() = request_user.to_string();
    // ... other work; another thread may set CURRENT_USER here ...
    let user = CURRENT_USER.lock().unwrap().clone();
    format!("account page for {user}")
}
