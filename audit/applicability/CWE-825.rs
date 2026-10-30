//@ compiles: unsafe
// CWE-825, expired pointer dereference: a pointer into a Vec is kept across a
// push that reallocates the buffer.
pub fn stale(v: &mut Vec<u32>) -> u32 {
    let first = v.as_ptr();
    v.push(1);
    unsafe { *first }
}
