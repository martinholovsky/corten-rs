//@ compiles: safe
// CWE-273, improper check for dropped privileges: the result of the privilege
// drop is discarded with `let _`, which silences #[must_use], and work goes on
// as if the drop succeeded. setuid is a stub for the OS call.
#[derive(Debug)]
pub struct Errno(pub i32);
pub fn setuid(_uid: u32) -> Result<(), Errno> { Err(Errno(1)) }
pub fn drop_and_run(uid: u32, job: impl FnOnce()) {
    let _ = setuid(uid);
    job();
}
