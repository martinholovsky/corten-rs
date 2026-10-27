//@ rejected: E0502
// CWE-825 attempted in safe Rust: a reference into the Vec cannot outlive a
// mutation that may reallocate it.
pub fn stale(v: &mut Vec<u32>) -> u32 {
    let first = &v[0];
    v.push(1);
    *first
}
