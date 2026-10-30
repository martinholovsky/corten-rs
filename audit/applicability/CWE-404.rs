//@ compiles: safe
// CWE-404, improper resource release. std::mem::forget is safe and skips the
// File's destructor, so the descriptor is never closed.
use std::fs::File;
pub fn probe(p: &str) -> std::io::Result<()> {
    let f = File::open(p)?;
    std::mem::forget(f);
    Ok(())
}
