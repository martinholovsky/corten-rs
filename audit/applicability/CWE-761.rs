//@ compiles: unsafe
// CWE-761, free of pointer not at start of buffer: a Box is rebuilt from an
// interior pointer and freed.
pub fn free_middle() {
    let b: Box<[u32; 4]> = Box::new([0; 4]);
    let p = Box::into_raw(b) as *mut u32;
    unsafe { drop(Box::from_raw(p.add(1))) };
}
