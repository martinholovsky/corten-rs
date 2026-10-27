//@ compiles: safe
// CWE-241, unexpected data type. The port is expected to be a number; a
// string such as "http" makes expect() panic and take the server down.
pub fn port(field: &str) -> u16 {
    field.parse().expect("port must be numeric")
}
