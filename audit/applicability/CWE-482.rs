//@ compiles: safe
// CWE-482, comparing instead of assigning: `==` was meant to be `=`; rustc
// only warns (unused comparison), so the counter is never reset.
pub fn reset(failed_attempts: &mut u32) {
    *failed_attempts == 0;
}
