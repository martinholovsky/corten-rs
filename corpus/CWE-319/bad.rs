//@ kind: checker
//@ expect: disallowed method
// CWE-319: sensitive data written to a plain TCP connection.
use std::io::Write;

pub fn send(token: &[u8]) -> std::io::Result<()> {
    let mut stream = std::net::TcpStream::connect(("203.0.113.7", 80))?;
    stream.write_all(token)
}

fn main() {}
