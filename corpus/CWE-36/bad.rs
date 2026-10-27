//@ expect: -F clippy::disallowed-methods
// CWE-36: a path built from input (an absolute path) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("/etc/passwd").map(|s| s.len()));
}
