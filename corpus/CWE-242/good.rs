use std::io::BufRead;
fn main() {
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(n) => println!("{n} bytes"),
        Err(e) => println!("{e}"),
    }
}
