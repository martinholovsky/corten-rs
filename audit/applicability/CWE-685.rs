//@ compiles: unsafe
// CWE-685, wrong number of arguments: the format asks for two values, one is
// passed; printf reads a garbage pointer for %s. Only foreign C-variadic
// functions accept an unchecked count, and calling one needs unsafe.
use std::ffi::{c_char, c_int};
unsafe extern "C" {
    fn printf(fmt: *const c_char, ...) -> c_int;
}
pub fn log(id: c_int) {
    unsafe {
        printf(c"%d %s\n".as_ptr(), id);
    }
}
