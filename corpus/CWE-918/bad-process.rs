//@ kind: checker
//@ expect: disallowed method
// CWE-918 process variant: a request to a caller-chosen URL by running curl. Refused: no ambient
// process authority (std::process::Command is banned).
pub fn fetch(target: &str) -> bool {
    std::process::Command::new("curl")
        .arg(format!("https://{target}"))
        .status()
        .is_ok_and(|s| s.success())
}

fn main() {}
