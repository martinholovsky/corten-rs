//@ kind: language
//@ deps: corten-std
//@ expect: sql!: a placeholder is inside quotes
// A placeholder written inside quotes, where it would be literal text.
fn main() {
    let name = "x' OR '1'='1";
    let _q = corten_std::sql!("SELECT id FROM users WHERE name = '{}'", name);
}
