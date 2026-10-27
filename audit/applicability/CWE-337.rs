//@ compiles: safe
// CWE-337, predictable seed in PRNG (also CWE-338/1241: an LCG is not a
// CSPRNG). The session token generator seeds from the current second, which
// an attacker can enumerate. std has no public RNG; hand-rolled ones are safe.
use std::time::{SystemTime, UNIX_EPOCH};
pub fn session_token() -> u64 {
    let mut x = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    x
}
