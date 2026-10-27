//@ compiles: safe
// CWE-599, missing validation of the peer certificate: the handshake result
// is used but the verification result (SSL_get_verify_result in OpenSSL) is
// never consulted. Both functions are stubs for the TLS library.
pub struct Conn;
pub fn handshake(_host: &str) -> Conn { Conn }
pub fn verify_result(_c: &Conn) -> Result<(), String> { Err("self-signed".into()) }
pub fn send_secret(host: &str, _secret: &[u8]) -> Conn {
    let c = handshake(host);
    c
}
