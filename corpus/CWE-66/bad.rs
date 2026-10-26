//@ expect: -F clippy::disallowed-methods
// CWE-66: a path built from input (a name that identifies a virtual resource) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("/proc/self/environ").map(|s| s.len()));
}
