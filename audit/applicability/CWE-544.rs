//@ compiles: safe
// CWE-544, no standardized error handling: one path returns a sentinel, one
// panics, one returns Option, so callers handle each inconsistently.
pub fn find_user(id: u32) -> i64 { if id == 0 { -1 } else { id as i64 } }
pub fn load_key(p: &str) -> Vec<u8> { std::fs::read(p).expect("key") }
pub fn quota(id: u32) -> Option<u64> { if id == 0 { None } else { Some(10) } }
