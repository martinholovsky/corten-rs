//@ compiles: safe
// CWE-338, cryptographically weak PRNG. A linear congruential generator
// produces a password-reset token; its output reveals its state. Rust lets
// any arithmetic be called "random"; nothing types a value as CSPRNG output.
pub struct Lcg(pub u64);
impl Lcg {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.0
    }
}
pub fn reset_token(rng: &mut Lcg) -> String { format!("{:016x}", rng.next()) }
