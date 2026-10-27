//@ compiles: safe
// CWE-14, compiler removal of code to clear buffers. The fill(0) is a dead
// store: the array is never read again and goes out of scope, so LLVM's
// dead-store elimination may delete it, leaving the password on the stack.
fn read_password() -> [u8; 32] { [7; 32] }
fn check(_pw: &[u8; 32]) -> bool { true }
pub fn login() -> bool {
    let mut pw = read_password();
    let ok = check(&pw);
    pw.fill(0);
    ok
}
