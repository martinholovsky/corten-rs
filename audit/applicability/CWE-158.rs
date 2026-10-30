//@ compiles: safe
// CWE-158, NUL not neutralized. Paths are sent NUL-separated (as to
// `xargs -0`); Rust strings may contain '\0', so "a\0/etc/shadow" becomes two
// entries downstream.
pub fn encode_paths(paths: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in paths {
        out.extend_from_slice(p.as_bytes());
        out.push(0);
    }
    out
}
