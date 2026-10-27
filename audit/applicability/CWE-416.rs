//@ compiles: unsafe
// CWE-416, use after free: a raw pointer to a Vec's buffer is read after the
// Vec is dropped.
pub fn use_after_free() -> u8 {
    let v = vec![1u8, 2, 3];
    let p = v.as_ptr();
    drop(v);
    unsafe { *p }
}
