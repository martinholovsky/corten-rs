//@ expect: E0120
// CWE-1079: a parent class without a virtual destructor. Rust has no inheritance or virtual destructors; a
// destructor for a trait object type is rejected.
trait Shape {
    fn area(&self) -> u32;
}
impl Drop for dyn Shape {
    fn drop(&mut self) {}
}
fn main() {}
