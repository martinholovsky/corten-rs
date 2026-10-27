//@ expect: -F unsafe-code
// CWE-476: dereferences a null pointer.
fn main() {
    let p: *const u32 = std::ptr::null();
    let v = unsafe { *p };
    println!("{v}");
}
