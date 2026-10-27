//@ compiles: safe
// CWE-463, deletion of a data-structure sentinel. A name lives NUL-terminated
// in a reused fixed slot; push() overwrites the terminator without writing a
// new one, so get() returns the name plus stale bytes of a longer earlier
// name. Bounds checks keep it inside the slot, not inside the data.
pub struct Slot {
    bytes: [u8; 16],
}
impl Slot {
    fn len(&self) -> usize {
        self.bytes.iter().position(|&b| b == 0).unwrap_or(16)
    }
    pub fn set(&mut self, name: &[u8]) {
        let n = name.len().min(15);
        self.bytes[..n].copy_from_slice(&name[..n]);
        self.bytes[n] = 0;
    }
    pub fn push(&mut self, b: u8) {
        let end = self.len();
        if end < 16 {
            self.bytes[end] = b;
        }
    }
    pub fn get(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }
}
