//@ compiles: safe
// CWE-606, unchecked input for loop condition. The iteration count comes
// from the request; 2^64-1 keeps the CPU busy indefinitely.
pub fn hash_rounds(input: &[u8], rounds_from_request: u64) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for _ in 0..rounds_from_request {
        for &b in input {
            h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
        }
    }
    h
}
