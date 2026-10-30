//@ compiles: unsafe
// CWE-415, double free: two Boxes rebuilt from one raw pointer are both dropped.
pub fn double_free() {
    let p = Box::into_raw(Box::new(5u32));
    unsafe {
        drop(Box::from_raw(p));
        drop(Box::from_raw(p));
    }
}
