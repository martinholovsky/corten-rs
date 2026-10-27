//@ expect: E0120
// CWE-1087: a class with a virtual method and no virtual destructor. Rust has no inheritance or virtual destructors; a
// destructor for a trait object type is rejected.
trait Shape {
    fn area(&self) -> u32;
}
impl Drop for dyn Shape {
    fn drop(&mut self) {}
}
fn main() {}
