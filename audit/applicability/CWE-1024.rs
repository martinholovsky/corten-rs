//@ compiles: safe
// CWE-1024, comparison of incompatible types. Rust refuses `u32 == i64`
// (see CWE-1024.implicit.rs), but a safe `as` cast makes the comparison
// compile: a request of 4_294_967_296 bytes truncates to 0 and passes.
pub fn within_quota(requested: u64, quota: u32) -> bool {
    (requested as u32) <= quota
}
