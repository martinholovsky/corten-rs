//@ compiles: safe
// CWE-601, open redirect: the `next` query parameter goes straight into the
// Location header, so https://evil.example is accepted.
pub fn after_login_redirect(next_param: &str) -> String {
    format!("HTTP/1.1 302 Found\r\nLocation: {next_param}\r\n\r\n")
}
