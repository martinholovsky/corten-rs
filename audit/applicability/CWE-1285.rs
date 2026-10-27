//@ compiles: safe
// CWE-1285, unvalidated index. Bounds checks turn an out-of-range index into
// a panic instead of a memory read, but the index is still unvalidated: an
// attacker-chosen slot number crashes the service.
pub fn slot_value(slots: &[u32], index_from_request: usize) -> u32 {
    slots[index_from_request]
}
