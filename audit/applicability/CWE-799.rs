//@ compiles: safe
// CWE-799, improper control of interaction frequency: password guesses are
// unlimited; nothing counts or delays attempts.
pub fn login(stored: &str, guess: &str) -> bool {
    stored == guess
}
