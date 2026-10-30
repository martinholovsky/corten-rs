//@ compiles: safe
// CWE-593, TLS context modified after sessions were created: a session copies
// the verify mode at creation (as OpenSSL's SSL_new does), so turning
// verification on in the shared context later leaves the live session
// unverified. TlsContext/Session are stubs for the TLS library.
use std::sync::{Arc, Mutex};
pub struct TlsContext { pub verify_peer: bool }
pub struct Session { pub verify_peer: bool }
pub fn new_session(ctx: &Arc<Mutex<TlsContext>>) -> Session {
    Session { verify_peer: ctx.lock().unwrap().verify_peer }
}
pub fn setup() -> Session {
    let ctx = Arc::new(Mutex::new(TlsContext { verify_peer: false }));
    let s = new_session(&ctx);
    ctx.lock().unwrap().verify_peer = true;
    s
}
