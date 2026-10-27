//@ expect: cannot be sent between threads safely
use corten_std::sync::LockRoot;
fn main() {
    let Some(mut root) = LockRoot::take() else { return };
    let token = root.token();
    let handle = std::thread::scope(|s| s.spawn(move || drop(token)).join());
    println!("{}", handle.is_ok());
}
