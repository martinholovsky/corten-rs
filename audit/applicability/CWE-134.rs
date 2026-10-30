//@ rejected: format argument must be a string literal
// CWE-134, externally controlled format string. Rust's formatting macros
// take the format only as a literal, checked at compile time; a runtime
// string as the format does not compile. The safe equivalent,
// format!("{}", user), treats the input as data.
pub fn render(user_input: &str) -> String {
    format!(user_input)
}
