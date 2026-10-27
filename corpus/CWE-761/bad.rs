//@ expect: -F unsafe-code
// CWE-761: frees a pointer that does not point at the start of its buffer.
fn main() {
    let p = Box::into_raw(Box::new([1u8, 2, 3])).cast::<u8>();
    unsafe { drop(Box::from_raw(p.add(1))) };
}
