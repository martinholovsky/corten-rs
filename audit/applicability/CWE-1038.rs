//@ compiles: safe
// CWE-1038, insecure automated optimizations. Release builds compile out
// debug_assert!, and the optimizer may remove the dead wipe of `secret`;
// both were meant as security measures and neither survives -O.
pub fn derive(secret: [u8; 16], len: usize) -> u8 {
    debug_assert!(len <= 16, "length check that vanishes in release builds");
    let mut secret = secret;
    let out = secret[0] ^ (len as u8);
    secret = [0; 16];
    let _ = secret;
    out
}
