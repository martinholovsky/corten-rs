//@ expect: E0120
// CWE-1045: a parent with a virtual destructor and a child without one. Rust has no inheritance or virtual destructors; a
// destructor for a trait object type is rejected.
trait Shape {
    fn area(&self) -> u32;
}
impl Drop for dyn Shape {
    fn drop(&mut self) {}
}
fn main() {}
