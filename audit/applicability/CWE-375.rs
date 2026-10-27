//@ compiles: safe
// CWE-375, returning a mutable object to an untrusted caller. The accessor
// hands out &mut to the internal role list, so callers can grant themselves
// roles without going through the checked API.
pub struct User {
    roles: Vec<String>,
}
impl User {
    pub fn roles(&mut self) -> &mut Vec<String> {
        &mut self.roles
    }
}
