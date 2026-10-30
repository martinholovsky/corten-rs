//@ compiles: safe
// CWE-392, missing report of error condition: a read or parse failure is
// turned into 0 ("no limit") and the caller never learns it failed.
pub fn load_limit(path: &str) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}
