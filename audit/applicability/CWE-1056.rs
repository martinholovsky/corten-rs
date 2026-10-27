//@ compiles: unsafe
// CWE-1056, callable with a variadic signature: on stable Rust only a foreign
// declaration inside `unsafe extern` may take `...`.
use std::ffi::{c_char, c_int};
unsafe extern "C" {
    pub fn printf(fmt: *const c_char, ...) -> c_int;
}
