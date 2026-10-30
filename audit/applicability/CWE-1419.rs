//@ compiles: safe
// CWE-1419, incorrect initialisation of a resource. The limiter starts with
// u32::MAX tokens instead of `max`, so the first window is unlimited.
pub struct RateLimiter {
    pub max: u32,
    pub remaining: u32,
}
impl RateLimiter {
    pub fn new(max: u32) -> Self {
        RateLimiter { max, remaining: u32::MAX }
    }
}
