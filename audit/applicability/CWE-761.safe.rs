//@ rejected: E0133
// CWE-761 attempted in safe Rust: ownership frees the allocation it owns; the
// only way to free an arbitrary interior pointer is unsafe.
pub fn free_middle() {
    let b: Box<[u32; 4]> = Box::new([0; 4]);
    let p = Box::into_raw(b) as *mut u32;
    drop(Box::from_raw(p.add(1)));
}
