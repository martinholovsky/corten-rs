//@ compiles: unsafe
// CWE-1058, a function used from many threads owns a mutable static with no
// synchronisation (`static mut`).
static mut LAST_USER: Option<String> = None;
pub fn handle(user: &str) {
    unsafe { *(&raw mut LAST_USER) = Some(user.to_owned()) };
}
