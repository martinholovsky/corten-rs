//@ expect: -F clippy::disallowed-methods
// CWE-38: a path built from input (a Windows absolute path) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("\\absolute\\pathname\\here").map(|s| s.len()));
}
