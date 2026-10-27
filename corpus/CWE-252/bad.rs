//@ expect: -F unused-must-use
// CWE-252: ignores a Result return value.
fn store(v: u32) -> Result<u32, String> {
    if v > 10 { Err("too big".to_owned()) } else { Ok(v) }
}
fn main() {
    store(30);
}
