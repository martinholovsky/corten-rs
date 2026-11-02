//@ kind: checker
//@ expect: disallowed method
// CWE-1428: an HTTP request where HTTPS is available.
use std::io::Write;

pub fn get(path: &str) -> std::io::Result<()> {
    let mut stream = std::net::TcpStream::connect(("api.example.com", 80))?;
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: api.example.com\r\n\r\n").as_bytes())
}

fn main() {}
