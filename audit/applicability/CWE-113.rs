//@ compiles: safe
// CWE-113, HTTP response splitting. A target of
// "/x\r\n\r\n<html>..." ends the headers early and injects a body.
pub fn redirect(target: &str) -> Vec<u8> {
    format!("HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\n\r\n").into_bytes()
}
