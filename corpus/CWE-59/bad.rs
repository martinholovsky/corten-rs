//@ expect: -F clippy::disallowed-methods
// CWE-59: a path built from input (a symbolic link planted in the directory) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("link-to-etc").map(|s| s.len()));
}
