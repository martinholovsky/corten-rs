//@ expect: -F unsafe-code
// CWE-416: reads an allocation after freeing it.
fn main() {
    let p = Box::into_raw(Box::new(5u32));
    unsafe { drop(Box::from_raw(p)) };
    let v = unsafe { *p };
    println!("{v}");
}
