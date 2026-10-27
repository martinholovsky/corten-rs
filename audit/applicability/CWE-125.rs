//@ compiles: unsafe
// CWE-125, out-of-bounds read: get_unchecked with an unvalidated index reads
// past the slice.
pub fn read_at(buf: &[u8], i: usize) -> u8 {
    unsafe { *buf.get_unchecked(i) }
}
