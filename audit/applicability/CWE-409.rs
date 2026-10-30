//@ compiles: safe
// CWE-409, highly compressed data. A run-length decoder trusts each run's
// 32-bit count, so 5 input bytes can expand to 4 GiB with no output cap.
pub fn decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for run in input.chunks_exact(5) {
        let n = u32::from_le_bytes([run[0], run[1], run[2], run[3]]) as usize;
        out.extend(std::iter::repeat(run[4]).take(n));
    }
    out
}
