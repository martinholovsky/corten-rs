//@ compiles: safe
// CWE-397, throws generic exception: Box<dyn Error> erases which failure
// happened, so callers cannot tell a missing file from a bad signature.
use std::error::Error;
pub fn load_license(path: &str) -> Result<String, Box<dyn Error>> {
    let s = std::fs::read_to_string(path)?;
    if !s.starts_with("SIG:") {
        return Err("bad".into());
    }
    Ok(s)
}
