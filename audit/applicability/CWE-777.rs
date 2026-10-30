//@ compiles: safe
// CWE-777, regular expression without anchors. Rust's de facto regex
// engines match anywhere by default (is_match is a search), so this
// validator accepts "1; rm -rf /". The engine is a stub (std has none).
fn regex_is_match(_pattern: &str, _input: &str) -> bool { unimplemented!("regex engine stub") }
pub fn is_numeric_id(input: &str) -> bool {
    regex_is_match(r"\d+", input)
}
