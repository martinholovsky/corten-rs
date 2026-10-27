//@ compiles: safe
// CWE-733, compiler optimization removes security-critical code. Wiping a
// Vec just before it is freed is a store with no later load; the optimizer
// may drop the loop, so the key bytes survive in freed heap memory.
pub fn use_key(key: Vec<u8>) -> usize {
    let n = key.iter().map(|b| *b as usize).sum();
    let mut key = key;
    for b in key.iter_mut() {
        *b = 0;
    }
    drop(key);
    n
}
