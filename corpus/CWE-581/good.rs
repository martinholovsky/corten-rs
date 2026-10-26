use std::collections::HashMap;
#[derive(PartialEq, Eq, Hash)]
struct Key(u32);
fn main() {
    let mut m = HashMap::new();
    m.insert(Key(1), "one");
    println!("{}", m.len());
}
