//@ expect: -F clippy::disallowed-methods
// CWE-29: a path built from input ('\\..\\filename') opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("\\..\\filename").map(|s| s.len()));
}
