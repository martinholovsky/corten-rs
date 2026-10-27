//@ compiles: safe
// CWE-756, missing custom error page: the raw Debug form of the error, with
// paths and internals, is sent to the client.
pub fn error_page(e: &dyn std::error::Error) -> String {
    format!("HTTP/1.1 500\r\n\r\n{e:?}")
}
