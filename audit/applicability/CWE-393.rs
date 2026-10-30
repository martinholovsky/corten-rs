//@ compiles: safe
// CWE-393, wrong status code: the write error is replaced by Ok(()).
pub fn write_audit(path: &str, line: &str) -> std::io::Result<()> {
    if let Err(_e) = std::fs::write(path, line) {
        return Ok(());
    }
    Ok(())
}
