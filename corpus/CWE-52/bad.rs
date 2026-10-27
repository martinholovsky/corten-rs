//@ expect: -F clippy::disallowed-methods
// CWE-52: a path built from input (multiple trailing slashes) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("/multiple/trailing/slash//").map(|s| s.len()));
}
