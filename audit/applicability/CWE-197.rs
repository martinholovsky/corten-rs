//@ compiles: safe
// CWE-197, numeric truncation. `as u16` drops the high bits: a checked
// "port" of 65616 truncates to 80.
pub fn port(n: u32) -> u16 {
    n as u16
}
