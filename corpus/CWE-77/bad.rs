//@ expect: -F clippy::disallowed-methods
// CWE-77: a command string built from input, run with ambient process authority.
fn run(name: &str) -> bool {
    std::process::Command::new("sh").arg("-c").arg(format!("tar -cf {name} data")).status().is_ok()
}

fn main() {
    println!("{}", run("x; rm -rf ~"));
}
