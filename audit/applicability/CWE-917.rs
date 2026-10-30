//@ compiles: safe
// CWE-917, expression language injection. The field name is spliced into an
// EL expression; "x}${runtime.exec('id')" escapes it. el_eval stands in for
// an expression-language evaluator embedded in a Rust web stack.
pub fn el_eval(_expr: &str) -> String {
    String::new()
}
pub fn show_field(field: &str) -> String {
    el_eval(&format!("${{user.{field}}}"))
}
