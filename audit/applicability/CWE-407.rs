//@ compiles: safe
// CWE-407, inefficient algorithmic complexity. De-duplicating with
// Vec::contains is quadratic in attacker-supplied input length.
pub fn dedupe(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for i in items {
        if !out.contains(i) {
            out.push(i.clone());
        }
    }
    out
}
