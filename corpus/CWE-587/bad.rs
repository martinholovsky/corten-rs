//@ expect: -F unsafe-code
// CWE-587: assigns a fixed address to a pointer and reads it.
fn main() {
    let p = std::ptr::without_provenance::<u32>(0x1000);
    let v = unsafe { *p };
    println!("{v}");
}
