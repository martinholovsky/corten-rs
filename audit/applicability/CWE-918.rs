//@ compiles: safe
// CWE-918, server-side request forgery: the server connects to whatever
// host:port the request names, including 127.0.0.1 or 169.254.169.254.
use std::io::{Read, Write};
use std::net::TcpStream;
pub fn fetch(target_from_request: &str, path: &str) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(target_from_request)?;
    write!(s, "GET {path} HTTP/1.0\r\n\r\n")?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    Ok(buf)
}
