#[derive(Clone)]
struct Account {
    id: u32,
    owner: String,
}
fn main() {
    let a = Account { id: 1, owner: "x".to_owned() };
    let b = a.clone();
    println!("{} {}", b.id, b.owner);
}
