//@ compiles: safe
// CWE-670, always-incorrect control flow: the loop returns on the first rule,
// so only rule 0 is ever evaluated.
pub fn allowed(rules: &[fn(&str) -> bool], req: &str) -> bool {
    for r in rules {
        return r(req);
    }
    false
}
