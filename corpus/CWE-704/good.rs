fn main() {
    let big: u32 = 300;
    match u8::try_from(big) {
        Ok(v) => println!("{v}"),
        Err(e) => println!("{e}"),
    }
}
