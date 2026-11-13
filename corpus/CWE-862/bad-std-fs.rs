//@ kind: checker
//@ expect: disallowed method
// CWE-862 variant: reading the protected directory's files through std. Refused:
// no ambient filesystem authority (std::fs is banned by the checker).
pub fn read_direct(path: &str) -> Option<Vec<u8>> {
    std::fs::read(format!("/srv/app/records/{path}")).ok()
}

fn main() {}
