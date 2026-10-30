//@ compiles: safe
// CWE-405, asymmetric resource consumption. A tiny request names its own
// work factor, so one small packet buys unbounded server CPU.
pub fn handle(rounds_from_client: u32, data: &[u8]) -> u64 {
    let mut h = 0u64;
    for _ in 0..rounds_from_client {
        for b in data {
            h = h.wrapping_mul(31).wrapping_add(*b as u64);
        }
    }
    h
}
