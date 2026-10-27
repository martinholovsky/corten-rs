//@ expect: -F clippy::disallowed-methods
// CWE-426: a program found through the PATH search, run with ambient process authority.
fn run(name: &str) -> bool {
    std::process::Command::new("tar").arg(name).status().is_ok()
}

fn main() {
    println!("{}", run("x; rm -rf ~"));
}
