//@ kind: checker
//@ expect: disallowed method
// CWE-288: an alternate path to a protected directory's files, through std.
// Refused: no ambient filesystem authority. (`take_dir` on a protected grant
// returns nothing at run time; that path is closed by construction and tested
// in corten-std, not here, since such a program builds.)
pub fn around(path: &str) -> Option<Vec<u8>> {
    std::fs::read(format!("/srv/app/records/{path}")).ok()
}

fn main() {}
