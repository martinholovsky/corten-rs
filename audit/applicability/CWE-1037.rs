//@ compiles: safe
// CWE-1037, processor optimization removes a security check. The bounds check
// before indexing (and Rust's own check inside []) can be bypassed under
// speculative execution (Spectre v1), leaking table[secret_byte] via cache.
pub fn lookup(data: &[u8], table: &[u8; 256 * 64], i: usize) -> u8 {
    if i < data.len() {
        table[data[i] as usize * 64]
    } else {
        0
    }
}
