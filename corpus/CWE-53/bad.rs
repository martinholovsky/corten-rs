//@ expect: -F clippy::disallowed-methods
// CWE-53: a path built from input (multiple internal backslashes) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("\\multiple\\\\internal\\backslash").map(|s| s.len()));
}
