//@ kind: checker
//@ expect: disallowed method
// CWE-319 variant: sensitive data in a plain UDP datagram.
pub fn send(token: &[u8]) -> std::io::Result<usize> {
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
    socket.send_to(token, ("203.0.113.7", 514))
}

fn main() {}
