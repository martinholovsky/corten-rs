//@ rejected: E0133
// CWE-680 attempted in safe Rust: the overflowing size can be computed, but
// filling past capacity needs raw writes; safe `push` grows the Vec, and
// `vec![0; n]` panics on a capacity overflow, so no buffer overflow follows.
pub fn table(count: usize) -> Vec<u64> {
    let mut v: Vec<u64> = Vec::with_capacity(count.wrapping_mul(8) / 8);
    for i in 0..count {
        v.as_mut_ptr().add(i).write(0);
    }
    v
}
