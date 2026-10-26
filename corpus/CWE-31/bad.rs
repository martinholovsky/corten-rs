//@ expect: -F clippy::disallowed-methods
// CWE-31: a path built from input ('dir\\..\\..\\filename') opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("dir\\..\\..\\filename").map(|s| s.len()));
}
