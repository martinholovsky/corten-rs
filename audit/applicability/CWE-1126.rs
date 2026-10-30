//@ compiles: safe
// CWE-1126, variable with unnecessarily wide scope: `buf` lives for the
// whole function but is used only inside the branch.
pub fn handle(flag: bool) -> usize {
    let mut buf = Vec::new();
    if flag {
        buf.extend_from_slice(b"data");
        return buf.len();
    }
    0
}
