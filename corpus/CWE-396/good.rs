fn parse(text: &str) -> Result<u32, std::num::ParseIntError> {
    text.parse()
}
fn main() {
    match parse("12") {
        Ok(v) => println!("{v}"),
        Err(e) => println!("{e}"),
    }
}
