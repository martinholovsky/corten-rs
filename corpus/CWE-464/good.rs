use std::ffi::CString;
fn main() {
    // An interior NUL is an error, not a silent truncation.
    match CString::new(b"ab\0cd".to_vec()) {
        Ok(s) => println!("{s:?}"),
        Err(e) => println!("{e}"),
    }
}
