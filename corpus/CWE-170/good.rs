use std::ffi::CStr;
fn main() {
    match CStr::from_bytes_until_nul(b"abc\0") {
        Ok(s) => println!("{s:?}"),
        Err(e) => println!("{e}"),
    }
}
