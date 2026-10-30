//@ compiles: safe
// CWE-697, incorrect comparison. Version strings compared lexically:
// "10.0" < "9.0" is true, so a minimum-version security gate accepts an
// old client. String's Ord is lexicographic by design.
pub fn version_ok(client: &str, minimum: &str) -> bool {
    client >= minimum
}
