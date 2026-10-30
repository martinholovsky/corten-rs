//@ compiles: unsafe
// CWE-562, return of stack variable address: the address of a local escapes as
// a raw pointer and is dereferenced after the frame is gone.
fn local_addr() -> *const u64 {
    let x = 42u64;
    &x as *const u64
}
pub fn read_dangling() -> u64 {
    unsafe { *local_addr() }
}
