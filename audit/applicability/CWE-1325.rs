//@ compiles: safe
// CWE-1325, sequential allocation without a total limit. Each record is
// capped at 1 MiB, but the number of records is not, so the sum is unbounded.
pub fn read_records(sizes: &[u32]) -> Vec<Vec<u8>> {
    sizes
        .iter()
        .map(|&n| vec![0u8; n.min(1 << 20) as usize])
        .collect()
}
