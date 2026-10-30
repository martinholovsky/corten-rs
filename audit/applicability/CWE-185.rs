//@ compiles: safe
// CWE-185, incorrect regular expression. std has no regex engine, so the
// engine is a stub; the weakness is the pattern: the unescaped "." matches
// any character, so "192x168y1z1" passes as an internal address.
fn regex_is_match(_pattern: &str, _input: &str) -> bool { unimplemented!("regex engine stub") }
pub fn is_internal_ip(addr: &str) -> bool {
    regex_is_match(r"^192.168.1.\d+$", addr)
}
