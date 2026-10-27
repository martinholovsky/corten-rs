//@ compiles: safe
// CWE-495, private data structure returned from a public method. The field
// is private but the accessor hands out &mut, so callers can add roles.
pub struct Account {
    roles: Vec<String>,
}
impl Account {
    pub fn roles(&mut self) -> &mut Vec<String> {
        &mut self.roles
    }
}
