//@ compiles: safe
// CWE-130, length parameter inconsistency. The echo reply trusts the length
// byte in the packet, not the number of bytes received, and the receive
// buffer is reused: a 2-byte packet claiming 200 bytes returns 199 bytes of
// earlier packets (Heartbleed's shape). Bounds checks only stop it leaving buf.
pub struct Rx {
    buf: [u8; 512],
}
impl Rx {
    pub fn echo(&mut self, pkt: &[u8]) -> &[u8] {
        self.buf[..pkt.len()].copy_from_slice(pkt);
        let claimed = self.buf[0] as usize;
        &self.buf[1..1 + claimed]
    }
}
