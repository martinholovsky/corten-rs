//@ compiles: safe
// CWE-176, improper handling of Unicode. Truncating by byte count assumes one
// byte per character; a name with a multi-byte character at the cut panics
// ("byte index is not a char boundary"), a remote denial of service.
pub fn short_name(name: &str) -> &str {
    if name.len() > 10 { &name[..10] } else { name }
}
