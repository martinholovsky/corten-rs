//@ compiles: safe
// CWE-703, improper check or handling of exceptional conditions: a missing
// account is treated as a zero balance rather than an error.
use std::collections::HashMap;
pub fn balance(accounts: &HashMap<String, i64>, who: &str) -> i64 {
    accounts.get(who).copied().unwrap_or(0)
}
