//@ compiles: safe
// CWE-372, incomplete internal state distinction. `Ready` is entered after the
// handshake whether or not login succeeded, and the write check looks only at
// the phase, conflating "ready, anonymous" with "ready, authenticated".
pub enum Phase {
    Handshake,
    Ready,
}
pub struct Session {
    pub phase: Phase,
    pub user: Option<String>,
}
pub fn can_write(s: &Session) -> bool {
    matches!(s.phase, Phase::Ready)
}
