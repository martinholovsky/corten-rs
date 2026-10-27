//@ expect: -F unsafe-code
// CWE-825: keeps a pointer into a vector across a reallocation.
fn main() {
    let mut v = vec![1u32];
    let p = v.as_ptr();
    v.reserve(1024);
    let first = unsafe { *p };
    println!("{first}");
}
