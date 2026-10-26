//@ edition: 2021
//@ expect: usage of the unsafe `no_mangle` attribute
// CWE-762 without the unsafe keyword: in edition 2021, #[no_mangle] can
// replace the C allocator's free(). Bypass-hunt variant; rejected.
#[no_mangle]
pub extern "C" fn free(_p: *mut u8) {}
fn main() {
    let v = vec![1u8];
    drop(v);
}
