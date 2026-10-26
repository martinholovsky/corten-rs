//@ expect: -F unsafe-code
// CWE-823: offsets a pointer beyond its allocation.
fn main() {
    let xs = [1u32, 2, 3];
    let v = unsafe { *xs.as_ptr().add(10) };
    println!("{v}");
}
