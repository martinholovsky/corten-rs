//@ compiles: safe
// CWE-613, insufficient session expiration: sessions record a creation time
// but lookup never compares it to now, so a stolen id works forever.
use std::collections::HashMap;
use std::time::SystemTime;
pub struct Session { pub user: String, pub created: SystemTime }
pub fn current_user<'a>(store: &'a HashMap<String, Session>, sid: &str) -> Option<&'a str> {
    store.get(sid).map(|s| s.user.as_str())
}
