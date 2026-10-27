//@ compiles: safe
// CWE-453, insecure default variable initialisation. The Default impl turns
// certificate verification off, and callers that use ..Default::default()
// inherit it.
pub struct ClientConfig {
    pub verify_tls: bool,
    pub timeout_secs: u64,
}
impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig { verify_tls: false, timeout_secs: 30 }
    }
}
