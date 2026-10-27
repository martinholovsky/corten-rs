use std::io::Write;
fn main() {
    let mut out = std::io::stdout().lock();
    if let Err(e) = writeln!(out, "written once") {
        println!("{e}");
    }
}
