pub struct Store {
    data: Vec<u32>,
}
impl Store {
    pub fn set(&mut self, data: &[u32]) {
        self.data = data.to_vec();
    }
}
fn main() {
    let mut s = Store { data: Vec::new() };
    s.set(&[1, 2]);
    println!("{:?}", s.data);
}
