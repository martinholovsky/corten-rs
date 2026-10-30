//@ compiles: safe
// CWE-455, non-exit on failed initialization: a malformed TLS config falls
// back to the default, which disables certificate verification.
#[derive(Default)]
pub struct TlsConfig { pub verify_peer: bool }
pub fn init(raw: &str) -> TlsConfig {
    parse(raw).unwrap_or_default()
}
fn parse(raw: &str) -> Result<TlsConfig, ()> {
    if raw == "verify" { Ok(TlsConfig { verify_peer: true }) } else { Err(()) }
}
