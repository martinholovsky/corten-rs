//@ compiles: safe
// CWE-1004, sensitive cookie without HttpOnly: the session cookie is set with
// Secure only, so page script can read it.
pub fn session_cookie(sid: &str) -> String {
    format!("Set-Cookie: sid={sid}; Path=/; Secure")
}
