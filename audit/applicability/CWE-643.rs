//@ compiles: safe
// CWE-643, XPath injection. "' or '1'='1" makes the predicate always true.
// xpath_eval stands in for an XPath engine.
pub fn xpath_eval(_expr: &str) -> Vec<String> {
    Vec::new()
}
pub fn login(user: &str, pass: &str) -> bool {
    !xpath_eval(&format!("//user[name='{user}' and pass='{pass}']")).is_empty()
}
