//@ compiles: unsafe
// CWE-134, externally controlled format string, reached through C's printf:
// the user's string is passed as the format, so `%n`/`%s` in it are honoured.
use std::ffi::{c_char, c_int, CString};
unsafe extern "C" {
    fn printf(fmt: *const c_char, ...) -> c_int;
}
pub fn log(user_input: &str) {
    let c = CString::new(user_input).unwrap_or_default();
    unsafe { printf(c.as_ptr()) };
}
