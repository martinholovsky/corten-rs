//@ compiles: safe
// CWE-1062, parent referencing a child: the trait (the "parent") names one
// of its implementors in its own interface.
pub trait Shape {
    fn area(&self) -> f64;
    fn as_circle(&self) -> Option<&Circle> {
        None
    }
}
pub struct Circle {
    pub r: f64,
}
impl Shape for Circle {
    fn area(&self) -> f64 {
        3.14 * self.r * self.r
    }
    fn as_circle(&self) -> Option<&Circle> {
        Some(self)
    }
}
