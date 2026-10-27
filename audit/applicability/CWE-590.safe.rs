//@ rejected: E0133
// CWE-590 attempted in safe Rust: safe code never frees explicitly; the only
// way to hand an arbitrary pointer to the allocator is unsafe.
pub fn free_stack() {
    let mut x = 7u32;
    drop(Box::from_raw(&mut x as *mut u32));
}
