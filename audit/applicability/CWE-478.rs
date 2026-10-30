//@ compiles: safe
// CWE-478, missing default case in a multiple-condition expression. A
// `match` must be exhaustive (see CWE-478.match.rs), but an if/else-if
// chain used as a statement needs no final else: an unknown role string
// leaves the privileged initial value in place.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Role { Admin, User, Guest }
pub fn role_from(s: &str) -> Role {
    let mut role = Role::Admin;
    if s == "user" {
        role = Role::User;
    } else if s == "guest" {
        role = Role::Guest;
    }
    role
}
