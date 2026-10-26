fn store(v: u32) -> Result<u32, String> {
    if v > 10 { Err("too big".to_owned()) } else { Ok(v) }
}
fn main() {
    match store(3) {
        Ok(v) => println!("{v}"),
        Err(e) => println!("{e}"),
    }
}
