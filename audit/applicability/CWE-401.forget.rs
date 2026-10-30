//@ compiles: safe
// CWE-401 variant: std::mem::forget is a safe function that leaks.
pub fn leak(v: Vec<u8>) {
    std::mem::forget(v);
}
