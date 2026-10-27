struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        println!("released");
    }
}
fn main() {
    let g = Guard;
    drop(g);
}
