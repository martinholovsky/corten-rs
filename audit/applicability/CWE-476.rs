//@ compiles: unsafe
// CWE-476, NULL pointer dereference: only raw pointers can be null, and
// dereferencing one needs unsafe.
pub fn read() -> i32 {
    let p: *const i32 = std::ptr::null();
    unsafe { *p }
}
