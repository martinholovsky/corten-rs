//@ expect: -F unsafe-code
// CWE-479: a signal handler that calls a non-reentrant function.
extern "C" fn on_signal(_sig: i32) {
    println!("signal");
}
unsafe extern "C" {
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
}
fn main() {
    let _previous = unsafe { signal(2, on_signal) };
}
