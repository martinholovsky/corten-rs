//@ compiles: safe
// CWE-480, incorrect operator: `|` was written where `&` was meant, so either
// condition alone grants access.
pub fn may_edit(authenticated: bool, is_owner: bool) -> bool {
    authenticated | is_owner
}
