//@ compiles: safe
// CWE-774, descriptors allocated without limits. Every request opens a file
// and keeps it, with no cap, until the process hits its fd limit.
use std::fs::File;
pub fn open_all(paths: &[String], held: &mut Vec<File>) -> std::io::Result<()> {
    for p in paths {
        held.push(File::open(p)?);
    }
    Ok(())
}
