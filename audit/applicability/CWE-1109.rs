//@ compiles: safe
// CWE-1109, same variable for multiple purposes: `n` is first a count,
// then a status code.
pub fn process(items: &[u8]) -> i32 {
    let mut n = items.len() as i32;
    if n > 10 {
        n = -1;
    }
    n
}
