//@ compiles: safe
// CWE-384, session fixation: on login the existing session id, possibly set
// by an attacker, is marked authenticated instead of a fresh id being issued.
use std::collections::HashMap;
pub struct Sessions { pub map: HashMap<String, Option<String>> }
impl Sessions {
    pub fn login(&mut self, sid: &str, user: &str) -> String {
        self.map.insert(sid.to_string(), Some(user.to_string()));
        sid.to_string()
    }
}
