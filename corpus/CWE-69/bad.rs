//@ expect: -F clippy::disallowed-methods
// CWE-69: a path built from input (an NTFS alternate data stream) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("file::$DATA").map(|s| s.len()));
}
