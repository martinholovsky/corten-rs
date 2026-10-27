//@ compiles: safe
// CWE-192, integer coercion error. A 64-bit length is coerced to u32 with
// `as`, which silently wraps: 0x1_0000_0010 becomes 16, and the check passes.
pub fn checked_len(n: u64) -> Option<u32> {
    let len = n as u32;
    if len <= 4096 { Some(len) } else { None }
}
