//@ compiles: safe
// CWE-209, error message containing sensitive information. The error sent
// to the client includes the connection string (with password) and the
// Debug form of the internal error.
fn connect(_dsn: &str) -> Result<(), std::io::Error> {
    Err(std::io::Error::other("auth failed"))
}
pub fn handle() -> Result<(), String> {
    let dsn = "postgres://app:S3cret@10.0.0.5/prod";
    connect(dsn).map_err(|e| format!("cannot connect to {dsn}: {e:?}"))
}
