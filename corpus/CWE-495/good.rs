pub struct Store {
    items: Vec<u32>,
}
impl Store {
    pub fn items(&self) -> &[u32] {
        &self.items
    }
}
fn main() {
    let s = Store { items: vec![1] };
    println!("{:?}", s.items());
}
