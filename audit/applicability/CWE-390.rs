//@ compiles: safe
// CWE-390, detection of error without action: the failure is detected and
// then ignored, so the secret temp file stays on disk.
pub fn cleanup(tmp: &std::path::Path) {
    if let Err(_e) = std::fs::remove_file(tmp) {}
}
