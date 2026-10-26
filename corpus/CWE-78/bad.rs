//@ expect: -F clippy::disallowed-methods
// CWE-78: an OS command string built from input, run with ambient process authority.
fn run(name: &str) -> bool {
    std::process::Command::new("sh").arg("-c").arg(format!("convert {name} out.png")).status().is_ok()
}

fn main() {
    println!("{}", run("x; rm -rf ~"));
}
