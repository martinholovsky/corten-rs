//@ compiles: safe
// CWE-834, excessive iteration: the iteration count comes from the request
// with no bound.
pub fn derive(rounds_from_request: u64, mut h: u64) -> u64 {
    for _ in 0..rounds_from_request {
        h = h.rotate_left(5) ^ 0x9e37_79b9;
    }
    h
}
