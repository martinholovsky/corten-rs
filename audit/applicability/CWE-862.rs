//@ compiles: safe
// CWE-862, missing authorization: any authenticated caller can delete any
// account; the caller is never checked against the action.
use std::collections::HashMap;
pub fn delete_account(accounts: &mut HashMap<String, String>, _caller: &str, target: &str) -> bool {
    accounts.remove(target).is_some()
}
