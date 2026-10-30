//@ compiles: safe
// CWE-1069, empty exception block: the error arm does nothing, so a failed
// delete of sensitive data goes unnoticed.
pub fn cleanup(path: &str) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(_) => {}
    }
}
