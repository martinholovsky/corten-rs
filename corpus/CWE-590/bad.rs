//@ expect: -F unsafe-code
// CWE-590: frees memory that was not allocated on the heap.
fn main() {
    let x = 5i32;
    let p = std::ptr::from_ref(&x).cast_mut();
    unsafe { drop(Box::from_raw(p)) };
}
