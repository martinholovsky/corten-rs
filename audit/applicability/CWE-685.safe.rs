//@ rejected: takes 2 arguments but 1 argument was supplied
// CWE-685: a Rust call with the wrong argument count is refused (E0061).
fn log(_id: i32, _who: &str) {}
pub fn caller() {
    log(1);
}
