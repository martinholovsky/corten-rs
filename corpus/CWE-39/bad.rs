//@ expect: -F clippy::disallowed-methods
// CWE-39: a path built from input (a drive-relative path) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("C:dirname").map(|s| s.len()));
}
