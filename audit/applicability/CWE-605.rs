//@ compiles: safe
// CWE-605, multiple binds to the same port: std sets SO_REUSEADDR on TCP
// listeners (non-Windows), and on macOS a second bind of 127.0.0.1:PORT
// succeeds while 0.0.0.0:PORT is held (measured, rustc 1.99.1), letting
// another process take the server's local connections.
use std::net::TcpListener;
pub fn serve(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind(("0.0.0.0", port))
}
pub fn steal(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", port))
}
