//@ compiles: safe
// CWE-195, signed to unsigned conversion error. A negative i32 from the
// client becomes a huge usize through `as`, and the allocation follows it.
pub fn alloc(n: i32) -> Vec<u8> {
    vec![0u8; n as usize]
}
