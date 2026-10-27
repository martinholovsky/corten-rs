//@ compiles: unsafe
// CWE-786, access before start of buffer: index computed as pos - 1 with pos 0
// reads the byte before the allocation.
pub fn previous(buf: &[u8], pos: isize) -> u8 {
    unsafe { *buf.as_ptr().offset(pos - 1) }
}
