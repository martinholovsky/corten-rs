//@ compiles: safe
// CWE-1284, unvalidated quantity. The record count comes from the file
// header and is used as an allocation size; a header of 2^60 aborts the
// process on allocation failure (capacity overflow or OOM).
pub fn read_records(header_count: u64) -> Vec<[u8; 64]> {
    Vec::with_capacity(header_count as usize)
}
