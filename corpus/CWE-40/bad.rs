//@ expect: -F clippy::disallowed-methods
// CWE-40: a path built from input (a UNC share) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("\\\\UNC\\share\\name\\").map(|s| s.len()));
}
