//@ expect: -F clippy::disallowed-methods
// CWE-626: a path built from input (an embedded NUL byte) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("avatar.php\0.png").map(|s| s.len()));
}
