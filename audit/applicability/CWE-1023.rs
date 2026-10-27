//@ compiles: safe
// CWE-1023, incomplete comparison with missing factors. The hand-written
// PartialEq compares only the user name and ignores the tenant, so
// "alice" in tenant B equals "alice" in tenant A for an authorization check.
pub struct Principal { pub tenant: u32, pub user: String }
impl PartialEq for Principal {
    fn eq(&self, other: &Self) -> bool {
        self.user == other.user
    }
}
pub fn may_access(owner: &Principal, caller: &Principal) -> bool {
    owner == caller
}
