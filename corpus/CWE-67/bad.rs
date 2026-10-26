//@ expect: -F clippy::disallowed-methods
// CWE-67: a path built from input (a Windows device name) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("CON").map(|s| s.len()));
}
