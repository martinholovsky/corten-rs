//@ expect: -F clippy::disallowed-methods
// CWE-1386: a path built from input (a junction or mount point inside the directory) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("junction/target").map(|s| s.len()));
}
