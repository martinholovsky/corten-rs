trait Shape {
    fn area(&self) -> u32;
}
struct Square(u32);
impl Shape for Square {
    fn area(&self) -> u32 {
        self.0.checked_mul(self.0).unwrap_or(u32::MAX)
    }
}
fn main() {
    let s: Box<dyn Shape> = Box::new(Square(2));
    println!("{}", s.area());
}
