//@ compiles: safe
// CWE-194, unexpected sign extension. A 16-bit signed length field is widened
// with `as u64`, which sign-extends: -1 becomes 0xFFFF_FFFF_FFFF_FFFF.
pub fn body_len(raw: i16) -> u64 {
    raw as u64
}
