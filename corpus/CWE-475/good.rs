fn main() {
    match std::str::from_utf8(&[0xff, 0x41]) {
        Ok(s) => println!("{s}"),
        Err(e) => println!("{e}"),
    }
}
