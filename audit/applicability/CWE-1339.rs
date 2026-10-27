//@ compiles: safe
// CWE-1339, insufficient precision: money summed in f32 drifts; 0.1 cannot be
// represented exactly.
pub fn total(prices: &[f32]) -> f32 {
    prices.iter().sum()
}
