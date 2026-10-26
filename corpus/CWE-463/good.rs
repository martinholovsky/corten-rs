use std::ffi::CString;
fn main() {
    match CString::new(b"ab".to_vec()) {
        Ok(s) => println!("{s:?}"),
        Err(e) => println!("{e}"),
    }
}
