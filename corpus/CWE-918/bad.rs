//@ kind: checker
//@ expect: disallowed method
// CWE-918: a request to a destination the caller chooses.
use std::io::Write;

pub fn fetch(host: &str) -> std::io::Result<()> {
    let mut stream = std::net::TcpStream::connect((host, 443))?;
    stream.write_all(b"GET / HTTP/1.1\r\n\r\n")
}

fn main() {}
