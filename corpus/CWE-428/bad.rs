//@ expect: -F clippy::disallowed-methods
// CWE-428: an unquoted program path with spaces, run with ambient process authority.
fn run(name: &str) -> bool {
    std::process::Command::new("C:\\Program Files\\Tool\\tool.exe").arg(name).status().is_ok()
}

fn main() {
    println!("{}", run("x; rm -rf ~"));
}
