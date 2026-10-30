//@ compiles: safe
// CWE-571, expression always true: an unsigned value is always >= 0, so
// this "check" admits everything; rustc only warns.
pub fn allowed(offset: u32) -> bool {
    offset >= 0
}
