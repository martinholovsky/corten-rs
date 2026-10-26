//@ expect: -F clippy::disallowed-methods
// CWE-51: a path built from input (multiple internal slashes) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("/multiple//internal/slash").map(|s| s.len()));
}
