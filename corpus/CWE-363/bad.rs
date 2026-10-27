//@ expect: -F clippy::disallowed-methods
// CWE-363: a path built from input (a link swapped in between check and use) opened with ambient
// filesystem access.
fn read_upload(name: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("uploads/{name}"))
}

fn main() {
    println!("{:?}", read_upload("race-link").map(|s| s.len()));
}
