//@ compiles: safe
// CWE-636, not failing securely. Result forces the error to be looked at,
// but unwrap_or(true) is a safe, one-token way to turn "policy service
// unreachable" into "allowed".
pub struct PolicyError;
fn policy_allows(_user: &str, _action: &str) -> Result<bool, PolicyError> { Err(PolicyError) }
pub fn authorize(user: &str, action: &str) -> bool {
    policy_allows(user, action).unwrap_or(true)
}
