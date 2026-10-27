//@ compiles: safe
// CWE-259, hard-coded password used for inbound authentication: the admin
// password is a literal in the binary.
const ADMIN_PASSWORD: &str = "letmein-2024";
pub fn admin_login(supplied: &str) -> bool {
    supplied == ADMIN_PASSWORD
}
