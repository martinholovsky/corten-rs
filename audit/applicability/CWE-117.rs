//@ compiles: safe
// CWE-117, improper output neutralization for logs. A user name containing
// "\n2026-01-01 INFO login ok for admin" forges a second log entry.
use std::io::Write;
pub fn log_failed_login<W: Write>(log: &mut W, user: &str) -> std::io::Result<()> {
    writeln!(log, "WARN login failed for {user}")
}
