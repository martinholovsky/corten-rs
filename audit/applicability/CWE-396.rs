//@ compiles: safe
// CWE-396, catch for generic exception: catch_unwind swallows every panic,
// including invariant violations, and the request carries on as allowed.
use std::panic::{catch_unwind, AssertUnwindSafe};
pub fn authorize(check: impl FnOnce() -> bool) -> bool {
    catch_unwind(AssertUnwindSafe(check)).unwrap_or(true)
}
