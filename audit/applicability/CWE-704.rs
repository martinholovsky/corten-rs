//@ compiles: safe
// CWE-704, incorrect type conversion. `c as u8` keeps only the low byte of a
// char, so U+012F ('į') passes an ASCII check as '/'.
pub fn has_slash(s: &str) -> bool {
    s.chars().any(|c| c as u8 == b'/')
}
