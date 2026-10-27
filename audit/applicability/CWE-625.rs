//@ compiles: safe
// CWE-625, permissive regular expression. "[a-zA-Z0-9]+" without anchors
// matches any input that contains one alphanumeric character, so the
// "safe filename" check accepts "../../etc/passwd". Engine is a stub.
fn regex_is_match(_pattern: &str, _input: &str) -> bool { unimplemented!("regex engine stub") }
pub fn safe_filename(name: &str) -> bool {
    regex_is_match(r"[a-zA-Z0-9]+", name)
}
