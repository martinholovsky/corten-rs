//@ expect: -F clippy::disallowed-methods
// CWE-427: a PATH value taken from input, run with ambient process authority.
fn run(name: &str) -> bool {
    std::process::Command::new("tar").env("PATH", name).arg("-c").status().is_ok()
}

fn main() {
    println!("{}", run("x; rm -rf ~"));
}
