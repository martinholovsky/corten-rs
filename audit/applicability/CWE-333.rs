//@ compiles: safe
// CWE-333, improper handling of insufficient entropy in a TRNG. When the
// OS entropy source fails, the key generator silently falls back to the
// clock, producing a guessable key instead of failing.
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};
pub fn key_bytes() -> [u8; 16] {
    let mut k = [0u8; 16];
    let ok = std::fs::File::open("/dev/random").and_then(|mut f| f.read_exact(&mut k)).is_ok();
    if !ok {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        k = t.to_le_bytes();
    }
    k
}
