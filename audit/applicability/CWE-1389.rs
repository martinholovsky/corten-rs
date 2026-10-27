//@ compiles: safe
// CWE-1389, parsing numbers with different radices. This parser reads "010"
// as decimal 10 while inet_aton-style parsers read it as octal 8, so the
// allow-list check and the connecting library disagree on the address.
pub fn octet(s: &str) -> Option<u8> {
    match s.strip_prefix("0x") {
        Some(h) => u8::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}
