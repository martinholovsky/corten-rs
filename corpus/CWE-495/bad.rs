//@ expect: E0596
// CWE-495: a public method hands out mutable access to private data
// through a shared reference.
pub struct Store {
    items: Vec<u32>,
}
impl Store {
    pub fn items(&self) -> &mut Vec<u32> {
        &mut self.items
    }
}
fn main() {
    let s = Store { items: vec![1] };
    s.items().push(2);
}
