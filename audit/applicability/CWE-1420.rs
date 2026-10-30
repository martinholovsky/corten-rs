//@ compiles: safe
// CWE-1420, exposure of sensitive information during transient execution.
// MITRE names software sandboxes and runtimes that rely on bounds checking,
// instead of hardware-enforced boundaries, as a way to introduce it. This is
// such a check in safe Rust: the CPU can speculate past `i < data.len()` (and
// past the check inside `[]`), load data[i] out of bounds, and leave
// table[secret * 64] in the cache, where a timing probe reads it (Spectre v1).
// Rust's bounds checks are architectural; they do not stop transient loads.
pub fn lookup(data: &[u8], table: &[u8; 256 * 64], i: usize) -> u8 {
    if i < data.len() {
        table[data[i] as usize * 64]
    } else {
        0
    }
}
