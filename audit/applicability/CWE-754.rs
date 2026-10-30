//@ compiles: safe
// CWE-754, improper check for unusual conditions: if metadata() fails the size
// limit is never applied and the upload is accepted.
pub fn accept_upload(path: &std::path::Path, max: u64) -> bool {
    if let Ok(m) = std::fs::metadata(path) {
        if m.len() > max {
            return false;
        }
    }
    true
}
