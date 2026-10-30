//@ compiles: safe
// CWE-1091, object used without invoking its destructor. Forgetting a
// BufWriter skips its Drop, so buffered data is never flushed and the file is
// never closed.
use std::fs::File;
use std::io::{BufWriter, Write};
pub fn save(p: &str, data: &[u8]) -> std::io::Result<()> {
    let mut w = BufWriter::new(File::create(p)?);
    w.write_all(data)?;
    std::mem::forget(w);
    Ok(())
}
