//@ compiles: safe
// CWE-1102, machine-dependent data representation: usize width and native
// byte order written to a file differ between targets.
pub fn save(path: &str, n: usize) -> std::io::Result<()> {
    std::fs::write(path, n.to_ne_bytes())
}
