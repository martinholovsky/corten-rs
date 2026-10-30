//@ compiles: safe
// CWE-222, truncation of security-relevant information. The audit record
// keeps only the first 32 characters of the request, so an attack payload
// after a long benign prefix is never recorded.
pub fn audit_line(user: &str, request: &str) -> String {
    let shown: String = request.chars().take(32).collect();
    format!("user={user} request={shown}")
}
