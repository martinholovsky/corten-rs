//@ compiles: safe
// CWE-135, multi-byte string length: the buffer is sized with the character
// count but filled with the UTF-8 bytes, so any non-ASCII name breaks it.
pub fn fixed_field(name: &str) -> Vec<u8> {
    let mut buf = vec![0u8; name.chars().count()];
    buf.copy_from_slice(name.as_bytes());
    buf
}
