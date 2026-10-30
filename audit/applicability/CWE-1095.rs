//@ compiles: safe
// CWE-1095, loop condition value updated inside the loop: the index is
// advanced in the body as well as by the loop step.
pub fn sum(v: &[u32]) -> u32 {
    let (mut i, mut s) = (0, 0);
    while i < v.len() {
        s += v[i];
        if v[i] == 0 {
            i += 2;
        }
        i += 1;
    }
    s
}
