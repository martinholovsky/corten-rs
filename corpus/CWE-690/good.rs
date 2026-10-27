use std::collections::HashMap;
fn main() {
    let names: HashMap<&str, &str> = HashMap::new();
    match names.get("user") {
        Some(n) => println!("{n}"),
        None => println!("missing"),
    }
}
