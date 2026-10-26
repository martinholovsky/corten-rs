//@ expect: -F unsafe-code
// CWE-467: sizes a copy with the size of a pointer instead of the data.
fn main() {
    let src = [1u64, 2];
    let mut dst = [0u64; 2];
    let n = std::mem::size_of::<*const u64>();
    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr().cast::<u8>(), dst.as_mut_ptr().cast::<u8>(), n) };
    println!("{dst:?}");
}
