//@ expect: -F unsafe-code
// CWE-468: scales a typed pointer offset by the element size again.
fn main() {
    let xs = [1u32, 2, 3, 4];
    let p = xs.as_ptr();
    let v = unsafe { *p.add(std::mem::size_of::<u32>()) };
    println!("{v}");
}
