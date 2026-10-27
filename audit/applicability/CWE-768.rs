//@ compiles: safe
// CWE-768, incorrect short-circuit evaluation: the audit call only runs when
// the cache misses, so cached reads are never logged.
pub fn read(cache_hit: bool, audit: &mut Vec<&'static str>) -> bool {
    cache_hit || log(audit)
}
fn log(a: &mut Vec<&'static str>) -> bool { a.push("read"); true }
