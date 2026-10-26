//@ expect: -F clippy::disallowed-methods
// CWE-64: a path built from input (a Windows shortcut) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("shortcut.lnk").map(|s| s.len()));
}
