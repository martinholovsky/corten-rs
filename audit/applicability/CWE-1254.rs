//@ compiles: safe
// CWE-1254, comparison logic over a series of steps. The token is compared
// in 4-byte chunks with an early exit, so timing reveals the first wrong chunk.
pub fn unlock(given: &[u8; 16], secret: &[u8; 16]) -> bool {
    for (a, b) in given.chunks(4).zip(secret.chunks(4)) {
        if a != b {
            return false;
        }
    }
    true
}
