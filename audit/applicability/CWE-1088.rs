//@ compiles: safe
// CWE-1088, synchronous remote access without timeout: connect and read have no
// timeout, so a silent peer hangs the caller indefinitely.
use std::io::Read;
use std::net::TcpStream;
pub fn fetch(addr: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(addr)?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    Ok(out)
}
