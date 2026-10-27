//@ expect: -F clippy::disallowed-methods
// CWE-45: a path built from input (multiple internal dots) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("file...name").map(|s| s.len()));
}
