//@ compiles: safe
// CWE-179, early validation: the path is validated, then transformed (percent
// sequences decoded) after the check, reintroducing "../".
pub fn open_target(raw: &str) -> Option<String> {
    if raw.contains("..") {
        return None;
    }
    Some(raw.replace("%2e", "."))
}
