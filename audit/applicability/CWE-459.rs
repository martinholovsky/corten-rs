//@ compiles: safe
// CWE-459, incomplete cleanup. The `?` on the parse returns early and skips
// the remove_file, leaving the temporary file with its contents behind.
use std::fs;
pub fn import(data: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let tmp = "/tmp/import.tmp";
    fs::write(tmp, data)?;
    let n: u32 = fs::read_to_string(tmp)?.trim().parse()?;
    fs::remove_file(tmp)?;
    Ok(n)
}
