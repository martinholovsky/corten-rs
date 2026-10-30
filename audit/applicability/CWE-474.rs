//@ compiles: safe
// CWE-474, function with inconsistent implementations: std documents that
// fs::rename's behavior when `to` exists differs between Unix and Windows.
pub fn replace_dir(from: &str, to: &str) -> std::io::Result<()> {
    std::fs::rename(from, to)
}
