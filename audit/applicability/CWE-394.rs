//@ compiles: safe
// CWE-394, unexpected return value: read() legitimately returns fewer bytes
// (or 0 at EOF); the code ignores n and processes the whole buffer, stale
// bytes included.
use std::io::Read;
pub fn next_message(r: &mut impl Read, buf: &mut [u8; 512]) -> std::io::Result<Vec<u8>> {
    let _n = r.read(buf)?;
    Ok(buf.to_vec())
}
