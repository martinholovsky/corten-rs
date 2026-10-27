//@ compiles: safe
// CWE-252, unchecked return value: both the Result and the byte count of
// write() are discarded, so failures and short writes go unnoticed.
use std::io::Write;
pub fn save(f: &mut std::fs::File, data: &[u8]) {
    let _ = f.write(data);
}
