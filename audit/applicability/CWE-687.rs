//@ compiles: safe
// CWE-687, wrong argument value: a timeout in seconds is passed to
// from_millis, making a 30-second timeout 30 milliseconds.
use std::time::Duration;
pub fn timeout(timeout_secs: u64) -> Duration {
    Duration::from_millis(timeout_secs)
}
