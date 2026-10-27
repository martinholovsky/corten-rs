//@ compiles: safe
// CWE-770, allocation without limits. One OS thread per accepted connection,
// with no cap on how many exist at once.
use std::net::TcpStream;
pub fn serve(conns: impl Iterator<Item = TcpStream>) {
    for c in conns {
        std::thread::spawn(move || drop(c));
    }
}
