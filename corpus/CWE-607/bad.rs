//@ expect: interior
// CWE-607: a public static that refers to a mutable object. Needs the
// interior-mutable-pub-static lint (not implemented).
use std::sync::Mutex;
pub static DEFAULTS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
fn main() {
    if let Ok(mut d) = DEFAULTS.lock() {
        d.push(1);
    }
}
