//@ compiles: safe
// CWE-73, external control of file name or path. The path to delete comes
// straight from the request with no allow-list.
pub fn delete(request_path: &str) -> std::io::Result<()> {
    std::fs::remove_file(request_path)
}
