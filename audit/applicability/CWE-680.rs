//@ compiles: unsafe
// CWE-680, integer overflow to buffer overflow: count * 8 wraps (release
// builds), the allocation is too small, and the raw writes run past it.
pub fn table(count: usize) -> Vec<u64> {
    let mut v: Vec<u64> = Vec::with_capacity(count.wrapping_mul(8) / 8);
    unsafe {
        for i in 0..count {
            v.as_mut_ptr().add(i).write(0);
        }
        v.set_len(count);
    }
    v
}
