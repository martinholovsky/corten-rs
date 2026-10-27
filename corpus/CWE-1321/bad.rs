//@ expect: E0608
// CWE-1321: modifies a shared prototype through a user-chosen key.
struct User {
    is_admin: bool,
}
fn main() {
    let u = User { is_admin: false };
    u["__proto__"] = true;
    println!("{}", u.is_admin);
}
