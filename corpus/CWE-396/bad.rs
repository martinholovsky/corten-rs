//@ expect: -F clippy::disallowed-methods
// CWE-396: a catch-all handler around arbitrary failure.
fn main() {
    let result = std::panic::catch_unwind(|| "12".parse::<u32>().ok());
    println!("{}", result.is_ok());
}
