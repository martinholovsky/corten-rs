struct User {
    is_admin: bool,
}
fn main() {
    let u = User { is_admin: false };
    println!("{}", u.is_admin);
}
