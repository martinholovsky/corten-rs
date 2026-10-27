//@ expect: E0369
// CWE-1235: arithmetic on boxed numbers. Boxes do not unbox implicitly.
fn main() {
    let n: Box<u32> = Box::new(5);
    let m = n + 1;
    println!("{m}");
}
