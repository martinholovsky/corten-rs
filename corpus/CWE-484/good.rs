fn label(v: u8) -> &'static str {
    match v {
        1 => "one",
        _ => "other",
    }
}
fn main() {
    println!("{}", label(1));
}
