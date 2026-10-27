//@ compiles: safe
// CWE-798, hard-coded credentials: an API token for an outbound service is a
// literal compiled into the binary and sent on every request.
const API_TOKEN: &str = "EXAMPLE-NOT-A-REAL-TOKEN";
pub fn authorization_header() -> String {
    format!("Authorization: Bearer {API_TOKEN}")
}
