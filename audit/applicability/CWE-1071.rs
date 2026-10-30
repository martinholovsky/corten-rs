//@ compiles: safe
// CWE-1071, empty code block: the failure branch is empty.
pub fn authorize(ok: bool) -> bool {
    if !ok {}
    true
}
