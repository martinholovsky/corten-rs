//@ expect: E0063
// CWE-580: a clone that does not copy every field.
struct Account {
    id: u32,
    owner: String,
}
impl Clone for Account {
    fn clone(&self) -> Self {
        Account { id: self.id }
    }
}
fn main() {
    let a = Account { id: 1, owner: "x".to_owned() };
    println!("{}", a.clone().owner);
}
