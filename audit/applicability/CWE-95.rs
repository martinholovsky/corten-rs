//@ compiles: safe
// CWE-95, eval injection. script_eval stands in for an embedded interpreter
// (Lua, Rhai, a JS engine); the input is evaluated as code, not data.
pub fn script_eval(_src: &str) -> String {
    String::new()
}
pub fn apply_discount(user_formula: &str) -> String {
    script_eval(&format!("return price * ({user_formula})"))
}
