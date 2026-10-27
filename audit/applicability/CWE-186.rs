//@ compiles: safe
// CWE-186, overly restrictive regular expression. The denylist pattern
// only catches lowercase "<script", so "<SCRIPT" slips through. The engine
// is a stub (std has none); the weakness is the pattern string.
fn regex_is_match(_pattern: &str, _input: &str) -> bool { unimplemented!("regex engine stub") }
pub fn looks_malicious(input: &str) -> bool {
    regex_is_match(r"<script", input)
}
