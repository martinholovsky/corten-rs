//@ expect: -F clippy::disallowed-methods
// CWE-23: a path built from input (a relative path that leaves the directory) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("../secret").map(|s| s.len()));
}
