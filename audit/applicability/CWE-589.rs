//@ compiles: safe
// CWE-589, non-ubiquitous API: Metadata::created returns Err where the
// platform or filesystem lacks birth time; unwrap turns that into a crash.
pub fn created(path: &str) -> std::time::SystemTime {
    std::fs::metadata(path).unwrap().created().unwrap()
}
