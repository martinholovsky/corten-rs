//@ expect: -F clippy::disallowed-methods
// CWE-37: a path built from input ('/absolute/pathname/here') opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("/absolute/pathname/here").map(|s| s.len()));
}
