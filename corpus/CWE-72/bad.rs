//@ expect: -F clippy::disallowed-methods
// CWE-72: a path built from input (an HFS+ alternate data stream) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("file/..namedfork/rsrc").map(|s| s.len()));
}
