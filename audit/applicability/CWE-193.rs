//@ compiles: safe
// CWE-193, off-by-one: the policy is three attempts, but `>` lets a fourth
// attempt through.
pub const MAX_ATTEMPTS: u32 = 3;
pub fn locked_out(failed_attempts: u32) -> bool {
    failed_attempts > MAX_ATTEMPTS
}
