//@ compiles: unsafe
// CWE-590, free of memory not on the heap: a stack local handed to Box::from_raw
// is "freed" by the global allocator on drop.
pub fn free_stack() {
    let mut x = 7u32;
    unsafe { drop(Box::from_raw(&mut x as *mut u32)) };
}
