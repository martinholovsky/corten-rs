//@ expect: -F clippy::disallowed-methods
// CWE-61: a path built from input (a UNIX symbolic link) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("symlink").map(|s| s.len()));
}
