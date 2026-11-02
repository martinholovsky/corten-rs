//@ kind: checker
//@ expect: disallowed method
// CWE-1428 process variant: an http:// URL by running curl. Refused: no ambient
// process authority (std::process::Command is banned).
pub fn fetch(target: &str) -> bool {
    std::process::Command::new("curl")
        .arg(format!("http://api.example.com/{target}"))
        .status()
        .is_ok_and(|s| s.success())
}

fn main() {}
