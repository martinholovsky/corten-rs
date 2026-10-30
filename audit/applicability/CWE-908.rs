//@ rejected: isn't initialized
// CWE-908, use of an uninitialised resource. Sending a buffer that was
// declared but never filled is rejected by rustc (E0381).
pub fn send(out: &mut Vec<u8>) {
    let buf: [u8; 16];
    out.extend_from_slice(&buf);
}
